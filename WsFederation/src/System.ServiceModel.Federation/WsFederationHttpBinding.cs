// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.IdentityModel.Tokens;
using System.ServiceModel.Channels;

namespace System.ServiceModel.Federation
{
    public class WsFederationHttpBinding : WSHttpBinding
    {
        // binding is always TransportWithMessageCredentialy
        public WsFederationHttpBinding(IssuedTokenParameters issuedTokenParameters) : base(SecurityMode.TransportWithMessageCredential)
        {
            IssuedTokenParameters = issuedTokenParameters ?? throw new ArgumentNullException(nameof(issuedTokenParameters));
        }

        public IssuedTokenParameters IssuedTokenParameters
        {
            get;
        }

        protected override SecurityBindingElement CreateMessageSecurity()
        {
            var issuedSecurityTokenParameters = IssuedTokenParameters.CreateIssuedSecurityTokenParameters();
            // TODO - brentsch - only BearerKey is supported
            issuedSecurityTokenParameters.KeyType = SecurityKeyType.BearerKey;
            issuedSecurityTokenParameters.RequireDerivedKeys = false;
            var result = new TransportSecurityBindingElement
            {
                IncludeTimestamp = true,
                // TODO - brentsch - need to update versions available to include WSSecurity1.1 and WsTrust 1.3.
                MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11BasicSecurityProfile10
            };

            if (issuedSecurityTokenParameters.KeyType == SecurityKeyType.BearerKey)
                result.EndpointSupportingTokenParameters.Signed.Add(issuedSecurityTokenParameters);
            else
                result.EndpointSupportingTokenParameters.Endorsing.Add(issuedSecurityTokenParameters);

            return result;
        }
    }
}
