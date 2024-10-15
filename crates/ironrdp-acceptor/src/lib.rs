#[macro_use]
extern crate tracing;

use ironrdp_async::bytes::Bytes;
use ironrdp_async::{single_sequence_step, Framed, FramedRead, FramedWrite, StreamWrapper};
use ironrdp_connector::credssp::KerberosConfig;
use ironrdp_connector::sspi::credssp::{self, CredSspServer, ServerError, ServerState};
use ironrdp_connector::sspi::negotiate::ProtocolConfig;
use ironrdp_connector::sspi::{self, AuthIdentity, Username};
use ironrdp_connector::{
    custom_err, general_err, ConnectorError, ConnectorErrorKind, ConnectorResult, ServerName, Written,
};
use ironrdp_core::{other_err, WriteBuf};

mod channel_connection;
mod connection;
mod finalization;
mod util;

pub use ironrdp_connector::DesktopSize;
use ironrdp_pdu::PduHint;

pub use self::channel_connection::{ChannelConnectionSequence, ChannelConnectionState};
pub use self::connection::{Acceptor, AcceptorResult, AcceptorState};
pub use self::finalization::{FinalizationSequence, FinalizationState};

pub enum BeginResult<S>
where
    S: StreamWrapper,
{
    ShouldUpgrade(S::InnerStream),
    Continue(Framed<S>),
}

pub async fn accept_begin<S>(mut framed: Framed<S>, acceptor: &mut Acceptor) -> ConnectorResult<BeginResult<S>>
where
    S: FramedRead + FramedWrite + StreamWrapper,
{
    let mut buf = WriteBuf::new();

    loop {
        if let Some(security) = acceptor.reached_security_upgrade() {
            let result = if security.is_empty() {
                BeginResult::Continue(framed)
            } else {
                BeginResult::ShouldUpgrade(framed.into_inner_no_leftover())
            };

            return Ok(result);
        }

        single_sequence_step(&mut framed, acceptor, &mut buf, None).await?;
    }
}

pub async fn accept_finalize<S>(
    mut framed: Framed<S>,
    acceptor: &mut Acceptor,
    server_name: ServerName,
    server_public_key: Vec<u8>,
    kerberos_config: Option<KerberosConfig>,
    mut unmatched: Option<&mut Vec<Bytes>>,
) -> ConnectorResult<(Framed<S>, AcceptorResult)>
where
    S: FramedRead + FramedWrite,
{
    let mut buf = WriteBuf::new();

    if acceptor.should_perform_credssp() {
        perform_credssp_step(
            &mut framed,
            acceptor,
            &mut buf,
            server_name,
            server_public_key,
            kerberos_config,
        )
        .await?;
    }

    loop {
        if let Some(result) = acceptor.get_result() {
            return Ok((framed, result));
        }
        single_sequence_step(&mut framed, acceptor, &mut buf, unmatched.as_deref_mut()).await?;
    }
}

#[derive(Clone, Copy, Debug)]
struct CredsspTsRequestHint;

const CREDSSP_TS_REQUEST_HINT: CredsspTsRequestHint = CredsspTsRequestHint;

impl PduHint for CredsspTsRequestHint {
    fn find_size(&self, bytes: &[u8]) -> ironrdp_core::DecodeResult<Option<(bool, usize)>> {
        match credssp::TsRequest::read_length(bytes) {
            Ok(length) => Ok(Some((true, length))),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(other_err!("CredsspTsRequestHint", source: e)),
        }
    }
}

#[derive(Debug)]
pub struct CredsspSequence<'a> {
    server: CredSspServer<CredentialsProxyImpl<'a>>,
    state: CredsspState,
    // selected_protocol: nego::SecurityProtocol,
}

#[derive(Debug)]
pub struct CredentialsProxyImpl<'a> {
    credentials: &'a AuthIdentity,
}

impl<'a> CredentialsProxyImpl<'a> {
    pub fn new(credentials: &'a AuthIdentity) -> Self {
        Self { credentials }
    }
}

impl credssp::CredentialsProxy for CredentialsProxyImpl<'_> {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: &Username) -> std::io::Result<Self::AuthenticationData> {
        assert_eq!(username.account_name(), self.credentials.username.account_name());

        Ok(self.credentials.clone())
    }
}

impl<'a> CredsspSequence<'a> {
    pub fn next_pdu_hint(&self) -> Option<&dyn PduHint> {
        match self.state {
            CredsspState::Ongoing => Some(&CREDSSP_TS_REQUEST_HINT),
            CredsspState::Finished(_) => None,
        }
    }

    pub fn init(
        creds: &'a AuthIdentity,
        server_name: ServerName,
        server_public_key: Vec<u8>,
        kerberos_config: Option<KerberosConfig>,
    ) -> ConnectorResult<(Self, credssp::TsRequest)> {
        let server_name = server_name.into_inner();
        let credentials = CredentialsProxyImpl::new(creds);
        let credssp_config: Box<dyn ProtocolConfig>;
        if let Some(ref krb_config) = kerberos_config {
            credssp_config = Box::new(Into::<sspi::KerberosConfig>::into(krb_config.clone()));
        } else {
            credssp_config = Box::<sspi::ntlm::NtlmConfig>::default();
        }

        debug!(?credssp_config);
        let server = CredSspServer::new(
            server_public_key,
            credentials,
            credssp::ClientMode::Negotiate(sspi::NegotiateConfig {
                protocol_config: credssp_config,
                package_list: None,
                client_computer_name: server_name,
            }),
        )
        .map_err(|e| ConnectorError::new("CredSSP", ConnectorErrorKind::Credssp(e)))?;

        let sequence = Self {
            server,
            state: CredsspState::Ongoing,
            // selected_protocol: protocol,
        };

        let initial_request = credssp::TsRequest::default();

        Ok((sequence, initial_request))
    }

    /// Returns Some(ts_request) when a TS request is received from client,
    pub fn decode_client_message(&mut self, input: &[u8]) -> ConnectorResult<Option<credssp::TsRequest>> {
        match self.state {
            CredsspState::Ongoing => {
                let message = credssp::TsRequest::from_buffer(input).map_err(|e| custom_err!("TsRequest", e))?;
                debug!(?message, "Received");
                Ok(Some(message))
            }
            _ => Err(general_err!(
                "attempted to feed client request to CredSSP sequence in an unexpected state"
            )),
        }
    }

    pub fn process_ts_request(&mut self, request: credssp::TsRequest) -> Result<ServerState, ServerError> {
        self.server.process(request)
    }

    pub fn handle_process_result(&mut self, result: ServerState, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let (size, next_state) = match self.state {
            CredsspState::Ongoing => {
                debug!(?result);
                let (ts_request_from_server, next_state) = match result {
                    ServerState::ReplyNeeded(ts_request) => (Some(ts_request), CredsspState::Ongoing),
                    ServerState::Finished(id) => (None, CredsspState::Finished(id)),
                };

                if let Some(ts_request) = ts_request_from_server {
                    debug!(?ts_request, "Send");
                    let written = write_credssp_request(ts_request, output)?;
                    Ok((Written::from_size(written)?, next_state))
                } else {
                    Ok((Written::Nothing, next_state))
                }
            }
            CredsspState::Finished(_) => Err(general_err!("CredSSP sequence is already done")),
        }?;

        fn write_credssp_request(ts_request: credssp::TsRequest, output: &mut WriteBuf) -> ConnectorResult<usize> {
            let length = usize::from(ts_request.buffer_len());
            let unfilled_buffer = output.unfilled_to(length);

            ts_request
                .encode_ts_request(unfilled_buffer)
                .map_err(|e| custom_err!("TsRequest", e))?;

            output.advance(length);

            Ok(length)
        }

        self.state = next_state;

        Ok(size)
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum CredsspState {
    Ongoing,
    Finished(AuthIdentity),
}

async fn perform_credssp_step<S>(
    framed: &mut Framed<S>,
    acceptor: &mut Acceptor,
    buf: &mut WriteBuf,
    server_name: ServerName,
    server_public_key: Vec<u8>,
    kerberos_config: Option<KerberosConfig>,
) -> ConnectorResult<()>
where
    S: FramedRead + FramedWrite,
{
    assert!(acceptor.should_perform_credssp());

    let creds = acceptor.creds.as_ref().unwrap();
    let username = Username::new(&creds.username, None).map_err(|e| custom_err!("invalid username", e))?;
    let identity = AuthIdentity {
        username,
        password: creds.password.clone().into(),
    };

    let (mut sequence, mut ts_request) =
        CredsspSequence::init(&identity, server_name, server_public_key, kerberos_config)?;

    loop {
        let server_state = sequence
            .process_ts_request(ts_request)
            .map_err(|e| custom_err!("ts request", e.error))?;
        buf.clear();
        let written = sequence.handle_process_result(server_state, buf)?;

        if let Some(response_len) = written.size() {
            let response = &buf[..response_len];
            trace!(response_len, "Send response");
            framed
                .write_all(response)
                .await
                .map_err(|e| ironrdp_connector::custom_err!("write all", e))?;
        }
        let Some(next_pdu_hint) = sequence.next_pdu_hint() else {
            break;
        };

        debug!(
            acceptor.state = ?acceptor.state,
            hint = ?next_pdu_hint,
            "Wait for PDU"
        );

        let pdu = framed
            .read_by_hint(next_pdu_hint, None)
            .await
            .map_err(|e| ironrdp_connector::custom_err!("read frame by hint", e))?;

        trace!(length = pdu.len(), "PDU received");

        if let Some(next_request) = sequence.decode_client_message(&pdu)? {
            ts_request = next_request;
        } else {
            break;
        }
    }

    acceptor.mark_credssp_as_done();

    Ok(())
}
