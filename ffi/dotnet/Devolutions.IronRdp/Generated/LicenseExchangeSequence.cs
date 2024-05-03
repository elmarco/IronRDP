// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.IronRdp.Diplomat;
#pragma warning restore 0105

namespace Devolutions.IronRdp;

#nullable enable

public partial class LicenseExchangeSequence: IDisposable
{
    private unsafe Raw.LicenseExchangeSequence* _inner;

    /// <summary>
    /// Creates a managed <c>LicenseExchangeSequence</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe LicenseExchangeSequence(Raw.LicenseExchangeSequence* handle)
    {
        _inner = handle;
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.LicenseExchangeSequence* AsFFI()
    {
        return _inner;
    }

    /// <summary>
    /// Destroys the underlying object immediately.
    /// </summary>
    public void Dispose()
    {
        unsafe
        {
            if (_inner == null)
            {
                return;
            }

            Raw.LicenseExchangeSequence.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~LicenseExchangeSequence()
    {
        Dispose();
    }
}