//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using JwtHeaderParameterNames = Microsoft.IdentityModel.JsonWebTokens.JwtHeaderParameterNames;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// Tests for OpenIdConnectProtocolValidator
    /// </summary>
    public class OpenIdConnectProtocolValidatorJsonWebTokenTests
    {
        private static JsonWebToken CreateValidatedIdToken()
        {
            return CreateValidatedIdToken(null);
        }

        private static JsonWebToken CreateValidatedIdToken(JProperty jProperty)
        {
            return CreateValidatedIdToken(jProperty, SecurityAlgorithms.RsaSha256);
        }

        private static JsonWebToken CreateValidatedIdToken(JProperty jProperty, string alg)
        {
            var payload = new JObject()
            {
                { JwtRegisteredClaimNames.Aud, Default.Audience },
                { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.UtcNow) },
                { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow) },
                { JwtRegisteredClaimNames.Iss, Default.Issuer },
                { JwtRegisteredClaimNames.Nonce, Default.Nonce },
                { JwtRegisteredClaimNames.Sub, Default.Subject }
            };

            if (jProperty != null)
            {
                if (payload.ContainsKey(jProperty.Name))
                {
                    payload.Remove(jProperty.Name);
                }
                payload.Add(jProperty);
            }
          
            var header = new JObject();
            if (alg != null)
                header[JwtHeaderParameterNames.Alg] = alg;

            return new JsonWebToken(header.ToString(), payload.ToString());
        }

        private static JsonWebToken CreateValidatedIdToken(List<JProperty> jProperties, string alg)
        {
            var payload = new JObject()
            {
                { JwtRegisteredClaimNames.Aud, Default.Audience },
                { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.UtcNow) },
                { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow) },
                { JwtRegisteredClaimNames.Iss, Default.Issuer },
                { JwtRegisteredClaimNames.Nonce, Default.Nonce },
                { JwtRegisteredClaimNames.Sub, Default.Subject }
            };

            if (jProperties != null)
            {
                foreach(var jProperty in jProperties)
                {
                    if (payload.ContainsKey(jProperty.Name))
                    {
                        payload.Remove(jProperty.Name);
                    }
                    payload.Add(jProperty);
                }            
            }

            var header = new JObject();
            if (alg != null)
                header[JwtHeaderParameterNames.Alg] = alg;

            return new JsonWebToken(header.ToString(), payload.ToString());
        }

        private static JsonWebToken CreateValidatedIdTokenWithoutNonce()
        {
            var payload = new JObject()
            {
                { JwtRegisteredClaimNames.Aud, Default.Audience },
                { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.UtcNow) },
                { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow) },
                { JwtRegisteredClaimNames.Iss, Default.Issuer },
                { JwtRegisteredClaimNames.Sub, Default.Subject }
            };

            var header = new JObject()
            {
                {JwtHeaderParameterNames.Alg, SecurityAlgorithms.RsaSha256 }
            };

            return new JsonWebToken(header.ToString(), payload.ToString());
        }

        private static JsonWebToken CreateValidatedIdTokenWithoutSub()
        {
            var payload = new JObject()
            {
                { JwtRegisteredClaimNames.Aud, Default.Audience },
                { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.UtcNow) },
                { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow) },
                { JwtRegisteredClaimNames.Iss, Default.Issuer },
                { JwtRegisteredClaimNames.Nonce, Default.Nonce },
            };

            var header = new JObject()
            {
                {JwtHeaderParameterNames.Alg, SecurityAlgorithms.RsaSha256 }
            };

            return new JsonWebToken(header.ToString(), payload.ToString());
        }

        [Fact]
        public void GenerateNonce()
        {
            List<string> errors = new List<string>();
            OpenIdConnectProtocolValidator protocolValidator = new OpenIdConnectProtocolValidator();
            string nonce = protocolValidator.GenerateNonce();
            int endOfTimestamp = nonce.IndexOf('.');
            if (endOfTimestamp == -1)
            {
                errors.Add("nonce does not have '.' seperator");
            }

            TestUtilities.AssertFailIfErrors("GenerateNonce", errors);
        }

        [Fact]
        public void GetSets()
        {
            OpenIdConnectProtocolValidator validationParameters = new OpenIdConnectProtocolValidator();
            Type type = typeof(OpenIdConnectProtocolValidator);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 10)
                Assert.True(true, "Number of properties has changed from 10 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                    {
                        new KeyValuePair<string, List<object>>("NonceLifetime", new List<object>{TimeSpan.FromMinutes(60), TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(100)}),
                        new KeyValuePair<string, List<object>>("RequireAcr", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireAmr", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireAuthTime", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireAzp", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireNonce", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("RequireSub", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("RequireTimeStampInNonce", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("RequireState", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("RequireStateValidation", new List<object>{true, false, true}),
                    },
                    Object = validationParameters,
                };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("OpenIdConnectProtocolValidator_GetSets", context.Errors);

            ExpectedException ee = ExpectedException.ArgumentNullException();
            Assert.NotNull(validationParameters.HashAlgorithmMap);
            Assert.Equal(18, validationParameters.HashAlgorithmMap.Count);

            ee = ExpectedException.ArgumentOutOfRangeException();
            try
            {
                validationParameters.NonceLifetime = TimeSpan.Zero;
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }

            ee = ExpectedException.ArgumentNullException();
            try
            {
                validationParameters.CryptoProviderFactory = null;
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }


        [Theory, MemberData(nameof(ValidateAuthenticationResponseTheoryData))]
        public void ValidateAuthenticationResponse(OidcProtocolValidatorJsonWebTokenTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateAuthenticationResponse", theoryData);
            try
            {
                theoryData.ProtocolValidator.ValidateAuthenticationResponse(theoryData.ValidationContext);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData> ValidateAuthenticationResponseTheoryData
        {
            get
            {
                var theoryData = new TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData>();

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException(),
                    First = true,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext == null"
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21333:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext.ProtocolMessage == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21334:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "'id_token' == null, 'code' == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext { ProtocolMessage = new OpenIdConnectMessage() }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21334:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "'id_token' == string.Empty, 'code' == string.Empty",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            Code = string.Empty,
                            IdToken = string.Empty,
                        }
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21332:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "'id_token' != null, validationContext.ValidatedJsonWebToken == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            IdToken = Guid.NewGuid().ToString()
                        }
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21335:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "'refresh_token' should not be returned from AuthorizationEndpoint",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            IdToken = Guid.NewGuid().ToString(),
                            RefreshToken = Guid.NewGuid().ToString()
                        },
                        ValidatedJsonWebToken = new JsonWebToken("{}","{}")
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator
                    {
                        RequireState = false
                    },
                    TestId = "'id_token' == string.Empty, 'code' != null, RequireState == false",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            Code = Guid.NewGuid().ToString(),
                            IdToken = string.Empty,
                        }
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21334:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator
                    {
                        RequireState = false
                    },
                    TestId = "'id_token' == null, 'code' == null, 'access_token' != null, RequireState == false",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            AccessToken = Guid.NewGuid().ToString(),
                            Code = string.Empty,
                            IdToken = string.Empty,
                        }
                    }
                });

                var protocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireTimeStampInNonce = true, RequireState = true };
                var nonce = protocolValidator.GenerateNonce();
                var state = Guid.NewGuid().ToString();
                var code = Guid.NewGuid().ToString();
                var accessToken = Guid.NewGuid().ToString();
                var chash256 = IdentityUtilities.CreateHashClaim(code, "SHA256");
                var athash256 = IdentityUtilities.CreateHashClaim(accessToken, "SHA256");
                var token = CreateValidatedIdToken(new List<JProperty> { new JProperty(JwtRegisteredClaimNames.Nonce,nonce), new JProperty(JwtRegisteredClaimNames.CHash, chash256), new JProperty(JwtRegisteredClaimNames.AtHash, athash256) }, SecurityAlgorithms.RsaSha256);
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = protocolValidator,
                    TestId = "ValidateAll",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                    {
                        State = state,
                        Nonce = nonce,
                        ProtocolMessage = new OpenIdConnectMessage { State = state, Code = code, IdToken = Guid.NewGuid().ToString(), AccessToken = accessToken },
#pragma warning disable 0618 // 'OpenIdConnectProtocolValidationContext.ValidatedIdToken' is obsolete.
                        ValidatedJsonWebToken = token
#pragma warning restore 0618 // 'OpenIdConnectProtocolValidationContext.ValidatedIdToken' is obsolete.
                    }
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidateTokenResponseTheoryData))]
        public void ValidateTokenResponse(OidcProtocolValidatorJsonWebTokenTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateTokenResponse", theoryData);
            try
            {
                theoryData.ProtocolValidator.ValidateTokenResponse(theoryData.ValidationContext);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData> ValidateTokenResponseTheoryData
        {
            get
            {
                var theoryData = new TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData>();

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException(),
                    First = true,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext == null"
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21333:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext.ProtocolMessage == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21336:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext.ProtocolMessage.IdToken == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage { AccessToken = Guid.NewGuid().ToString() }
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21336:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext.ProtocolMessage.AccessToken == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage { IdToken = Guid.NewGuid().ToString() }
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21332:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext.ValidatedJsonWebToken == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            AccessToken = Guid.NewGuid().ToString(),
                            IdToken = Guid.NewGuid().ToString()
                        }
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator
                    {
                        RequireNonce = false,
                        RequireTimeStampInNonce = false
                    },
                    TestId = "validationContext.ValidatedJsonWebToken.AtHash == null (Optional)",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                    {
                        Nonce = Default.Nonce,
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            AccessToken = Guid.NewGuid().ToString(),
                            IdToken = Guid.NewGuid().ToString()
                        },
                        ValidatedJsonWebToken = CreateValidatedIdToken()
                    }
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidateUserInfoResponseTheoryData))]
        public void ValidateUserInfoResponse(OidcProtocolValidatorJsonWebTokenTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateUserInfoResponse", theoryData);
            try
            {
                theoryData.ProtocolValidator.ValidateUserInfoResponse(theoryData.ValidationContext);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData> ValidateUserInfoResponseTheoryData
        {
            get
            {
                var theoryData = new TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData>();

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException(),
                    First = true,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext == null"
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21337:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext.UserInfoEndpointResponse == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21332:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext.ValidatedJsonWebToken == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext { UserInfoEndpointResponse = "response" }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21343:", typeof(JsonReaderException)),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "UserInfoEndpointResponse is not valid JSON",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        UserInfoEndpointResponse = "response",
                        ValidatedJsonWebToken = CreateValidatedIdToken(),
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21345:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "UserInfoEndpointResponse.sub == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        UserInfoEndpointResponse = @"{ ""tid"":""42"",""name"":""bob""}",
                        ValidatedJsonWebToken = CreateValidatedIdToken(),
                    }
                });

                var jwtWithoutSub = CreateValidatedIdTokenWithoutSub();
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21346:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "ValidatedIdToken.sub == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        UserInfoEndpointResponse =  @"{ ""sub"": ""sub1""}",
                        ValidatedJsonWebToken = jwtWithoutSub
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21338:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "UserInfoEndpointResponse.sub != ValidatedIdToken.sub",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        UserInfoEndpointResponse =  @"{ ""sub"": ""sub1""}",
                        ValidatedJsonWebToken = CreateValidatedIdToken()
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "(JSON) UserInfoResponse.sub == ValidatedIdToken.sub",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        UserInfoEndpointResponse =  @"{ ""sub"": ""sub""}",
                        ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty("sub", "sub"))
                    }
                });

                var payload = new JObject()
                {
                    { JwtRegisteredClaimNames.Aud, Default.Audience },
                    { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.UtcNow) },
                    { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow) },
                    { JwtRegisteredClaimNames.Iss, Default.Issuer },
                    { JwtRegisteredClaimNames.Nonce, Default.Nonce },
                    { JwtRegisteredClaimNames.Sub, "sub" }
                }.ToString();

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "(JWT) UserInfoResponse.sub == ValidatedIdToken.sub",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        UserInfoEndpointResponse = new JsonWebTokenHandler().CreateToken(payload, Default.AsymmetricSigningCredentials),
                        ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty("sub", "sub"))
                    }
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidateIdTokenTheoryData))]
        public void ValidateIdToken(OidcProtocolValidatorJsonWebTokenTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateIdToken", theoryData);

            // should put this in ValidationContext
            theoryData.ValidationContext.ValidatedJsonWebToken = theoryData.JsonWebToken;

            try
            {
                theoryData.ProtocolValidator.PublicValidateIdToken(theoryData.ValidationContext);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            return;
        }

        public static TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData> ValidateIdTokenTheoryData
        {
            get
            {
                var theoryData = new TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData>();

                var validationContext = new OpenIdConnectProtocolValidationContext
                {
                    ProtocolMessage = new OpenIdConnectMessage()
                };

                var payload = new JObject();
                payload[JwtRegisteredClaimNames.Exp] = EpochTime.GetIntDate(DateTime.UtcNow).ToString();
                var jwt = new JsonWebToken("{}", payload.ToString());
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21314:"),
                    First = true,
                    JsonWebToken = jwt,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "aud == null",
                    ValidationContext = validationContext,
                });

                payload = new JObject();
                payload[JwtRegisteredClaimNames.Aud] = Default.Audience;
                jwt = new JsonWebToken("{}", payload.ToString());
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21314:"),
                    JsonWebToken = jwt,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "exp == null",
                    ValidationContext = validationContext
                });

                payload = new JObject();
                payload[JwtRegisteredClaimNames.Aud] = Default.Audience;
                payload[JwtRegisteredClaimNames.Exp] = EpochTime.GetIntDate(DateTime.UtcNow).ToString();
                jwt = new JsonWebToken("{}", payload.ToString());

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21314:"),
                    JsonWebToken = jwt,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "iat == null",
                    ValidationContext = validationContext
                });

                payload = new JObject();
                payload[JwtRegisteredClaimNames.Aud] = Default.Audience;
                payload[JwtRegisteredClaimNames.Exp] = EpochTime.GetIntDate(DateTime.UtcNow).ToString();
                payload[JwtRegisteredClaimNames.Iat] = EpochTime.GetIntDate(DateTime.UtcNow).ToString();
                payload[JwtRegisteredClaimNames.Sub] = Default.Subject;
                jwt = new JsonWebToken("{}", payload.ToString());

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21314:"),
                    JsonWebToken = jwt,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "iss == null",
                    ValidationContext = validationContext,
                });

                payload = new JObject();
                payload[JwtRegisteredClaimNames.Aud] = Default.Audience;
                payload[JwtRegisteredClaimNames.Exp] = EpochTime.GetIntDate(DateTime.UtcNow).ToString();
                payload[JwtRegisteredClaimNames.Iat] = EpochTime.GetIntDate(DateTime.UtcNow).ToString();
                payload[JwtRegisteredClaimNames.Iss] = Default.Issuer;

                jwt = new JsonWebToken("{}", payload.ToString());
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    JsonWebToken = jwt,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator
                    {
                        RequireSub = false
                    },
                    TestId = "sub == null, RequireSub == false",
                    ValidationContext = validationContext
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21314:"),
                    JsonWebToken = jwt,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "sub == null, RequireSub == true",
                    ValidationContext = validationContext
                });

                new PublicOpenIdConnectJsonWebTokenProtocolValidator
                {
                    RequireAcr = true,
                };

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21315:"),
                    JsonWebToken = CreateValidatedIdToken(),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireAcr = true },
                    TestId = "'acr' == null, RequireAcr == true",
                    ValidationContext = validationContext
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21316:"),
                    JsonWebToken = CreateValidatedIdToken(),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireAmr = true },
                    TestId = "amr == null, RequireAmr == true",
                    ValidationContext = validationContext
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21317:"),
                    JsonWebToken = CreateValidatedIdToken(),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireAuthTime = true },
                    TestId = "auth_time == null, RequireAuthTime == true",
                    ValidationContext = validationContext
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    JsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Aud, Default.Audiences)),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "multiple 'aud' no 'azp' warning only",
                    ValidationContext = validationContext
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21318:"),
                    JsonWebToken = CreateValidatedIdToken(),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireAzp = true },
                    TestId = "azp == null",
                    ValidationContext = validationContext
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21308:"),
                    JsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Azp, Default.Azp)),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireAzp = true },
                    TestId = "'azp' != null, validationContext.ClientId == null",
                    ValidationContext = validationContext
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21340:"),
                    JsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Azp, Default.Azp)),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireAzp = true },
                    TestId = "azp claim != validationContext.ClientId",
                    ValidationContext = new OpenIdConnectProtocolValidationContext { ClientId = Default.ClientId }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    JsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Azp, Default.Azp)),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireAzp = true },
                    TestId = "azp claim == validationContext.ClientId",
                    ValidationContext = new OpenIdConnectProtocolValidationContext { ClientId = Default.Azp },
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21313:", typeof(InvalidOperationException)),
                    JsonWebToken = CreateValidatedIdToken(),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator
                    {
                        JsonWebTokenValidator = ((jwtToken, context) => { throw new InvalidOperationException("Validator"); })
                    },
                    TestId = "IdTokenValidator throws InvalidOperation",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    JsonWebToken = new JsonWebToken("{}","{}"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator
                    {
                        JsonWebTokenValidator = ((jwtToken, context) => { return; })
                    },
                    TestId = "IdTokenValidator returns",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21313:", typeof(InvalidOperationException)),
                    JsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Acr, Default.Acr)),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator
                    {
                        JsonWebTokenValidator = ((jwtToken, context) =>
                       {
                           var JsonWebToken = jwtToken as JsonWebToken;
                           if (JsonWebToken.TryGetPayloadValue(JwtRegisteredClaimNames.Acr, out string acr) && acr != "acr")
                               throw new InvalidOperationException();
                       })
                    },
                    TestId = "IdTokenValidator throws if no acr",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidateCHashTheoryData))]
        private void ValidateCHash(OidcProtocolValidatorJsonWebTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateCHash", theoryData);
            try
            {
                theoryData.ProtocolValidator.PublicValidateCHash(theoryData.ValidationContext);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);

            return;
        }

        public static TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData> ValidateCHashTheoryData
        {
            get
            {
                var jsonWebTokenHandler = new JsonWebTokenHandler();
                string code = Guid.NewGuid().ToString();
                string chash256 = IdentityUtilities.CreateHashClaim(code, "SHA256");
                string chash384 = IdentityUtilities.CreateHashClaim(code, "SHA384");
                string chash512 = IdentityUtilities.CreateHashClaim(code, "SHA512");

                return new TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData>
                {
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        First = true,
                        TestId = "validationContext == null"
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21332:"),
                        TestId = "validationContext.ValidatedJsonWebToken == null",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage()
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21333:"),
                        TestId = "validationContext.ProtocolMessage == null",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ValidatedJsonWebToken = CreateValidatedIdToken()
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        TestId = "ProtocolMessage.Code == null",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage(),
                            ValidatedJsonWebToken = CreateValidatedIdToken()
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX21307:"),
                        TestId = "ValidatedIdToken.chash == null",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = Guid.NewGuid().ToString() },
                            ValidatedJsonWebToken = CreateValidatedIdToken()
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX21347:", typeof(OpenIdConnectProtocolException)),
                        TestId = "ValidatedIdToken.chash == string.Empty",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = Guid.NewGuid().ToString() },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, string.Empty))
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(ArgumentNullException), "IDX10000:"),
                        TestId = "ValidatedIdToken.Header.alg == 'None'",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash256), SecurityAlgorithms.None)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(ArgumentNullException), "IDX10000:"),
                        TestId = "ValidatedIdToken.Header.alg == null",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash256), null)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(ArgumentNullException), "IDX10000:"),
                        TestId = "ValidatedIdToken.Header.alg == string.empty",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash256), "")
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        TestId = "alg==256, hash(code)==256",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash256), SecurityAlgorithms.RsaSha256)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        TestId = "alg==384, hash(code)==384",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash384), SecurityAlgorithms.RsaSha384)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        TestId = "alg==512, hash(code)==512",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash512), SecurityAlgorithms.RsaSha512)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX21347:", typeof(OpenIdConnectProtocolException)),
                        TestId = "ValidatedIdToken.chash != ProtocolMessage.Code",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = Guid.NewGuid().ToString() },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash256), SecurityAlgorithms.RsaSha256)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX21347:", typeof(OpenIdConnectProtocolException)),
                        TestId = "alg==256, hash(code)==384",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash384), SecurityAlgorithms.RsaSha256)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX21347:", typeof(OpenIdConnectProtocolException)),
                        TestId = "alg==256, hash(code)==384",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash384), SecurityAlgorithms.RsaSha256)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX21347:", typeof(OpenIdConnectProtocolException)),
                        TestId = "alg==256, hash(code)==384",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash384), SecurityAlgorithms.RsaSha256)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX21347:", typeof(OpenIdConnectProtocolException)),
                        TestId = "alg==256, hash(code)==512",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash512), SecurityAlgorithms.RsaSha256)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX21347:", typeof(OpenIdConnectProtocolException)),
                        TestId = "alg==384, hash(code)==512",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash512), SecurityAlgorithms.RsaSha384)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX21347:", typeof(OpenIdConnectProtocolException)),
                        TestId = "alg==384, hash(code)==256",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = code },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, chash256), SecurityAlgorithms.RsaSha384)
                        }
                    },
                    new OidcProtocolValidatorJsonWebTokenTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX21306:"),
                        TestId = "ValidatedIdToken.chash is not a string, but array",
                        ValidationContext = new OpenIdConnectProtocolValidationContext
                        {
                            ProtocolMessage = new OpenIdConnectMessage { Code = Guid.NewGuid().ToString() },
                            ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.CHash, new List<string> { "chash1", "chash2" }))
                        }
                    }
                    // The test case below cannot be recreated using the Microsoft.IdentityModel.JsonWebTokens library, as it is impossible to add a duplicate property
                    // to a JObject.

                    //new OidcProtocolValidatorTheoryData
                    //{
                    //    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX21306:"),
                    //    TestId = "Multiple chashes",
                    //    ValidationContext = new OpenIdConnectProtocolValidationContext
                    //    {
                    //        ProtocolMessage = new OpenIdConnectMessage { Code = code },
                    //        ValidatedIdToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(new JObject() { { JwtRegisteredClaimNames.CHash, chash256 }, { JwtRegisteredClaimNames.CHash, chash512 } }.ToString(), Default.AsymmetricSigningCredentials))
                    //    }
                    //}
                };
            }
        }

        [Theory, MemberData(nameof(ValidateNonceTheoryData))]
        private void ValidateNonce(OidcProtocolValidatorJsonWebTokenTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateNonce", theoryData);
            try
            {
                theoryData.ProtocolValidator.PublicValidateNonce(theoryData.ValidationContext);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData> ValidateNonceTheoryData
        {
            get
            {
                var theoryData = new TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData>();

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException(),
                    First = true,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext == null",
                });
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21332:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext.ValidatedJsonWebToken == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage()
                    }
                });

                var jwtWithoutNonce = CreateValidatedIdTokenWithoutNonce();
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21320:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = true },
                    TestId = "validationContext.Nonce == null, jwt.Nonce == null, RequireNonce == true",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ValidatedJsonWebToken = jwtWithoutNonce
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21323:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = true },
                    TestId = "validationContext.Nonce == null, jwt.Nonce != null, RequireNonce == true",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ValidatedJsonWebToken = CreateValidatedIdToken()
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21349:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = true },
                    TestId = "validationContext.Nonce != null, jwt.Nonce == null, RequireNonce == true",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        Nonce = Default.Nonce,
                        ValidatedJsonWebToken = jwtWithoutNonce
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = false },
                    TestId = "validationContext.Nonce == null, jwt.Nonce == null, RequireNonce == false",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ValidatedJsonWebToken = jwtWithoutNonce
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21323:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = false },
                    TestId = "validationContext.Nonce == null, jwt.Nonce != null, RequireNonce == false",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ValidatedJsonWebToken = CreateValidatedIdToken()
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21349:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = false },
                    TestId = "validationContext.Nonce != null, jwt.Nonce == null, RequireNonce == false",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        Nonce = Default.Nonce,
                        ValidatedJsonWebToken = jwtWithoutNonce
                    }
                });

                var protocolValidatorRequiresTimeStamp = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireTimeStampInNonce = true };
                var nonce = protocolValidatorRequiresTimeStamp.GenerateNonce();
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = false },
                    TestId = "nonce.timestamp == true, RequireTimeStampInNonce == true",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        Nonce = nonce,
                        ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Nonce, nonce))
                    }
                });

                var protocolValidatorDoesNotRequireTimeStamp = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireTimeStampInNonce = false };
                var nonceWithoutTimestamp = protocolValidatorDoesNotRequireTimeStamp.GenerateNonce();
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21325:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = false, RequireTimeStampInNonce = true },
                    TestId = "nonce.timestamp == false, RequireTimeStampInNonce == true",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        Nonce = nonceWithoutTimestamp,
                        ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Nonce, nonceWithoutTimestamp ))
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21321:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = false, RequireTimeStampInNonce = true },
                    TestId = "ValidationContext.Nonce != Jwt.Nonce",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        Nonce = protocolValidatorRequiresTimeStamp.GenerateNonce(),
                        ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Nonce, protocolValidatorRequiresTimeStamp.GenerateNonce()))
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21326:", typeof(FormatException)),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = false, RequireTimeStampInNonce = true },
                    TestId = "Nonce timestamp is not formated as a int",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        Nonce = "abc.abc",
                        ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Nonce, "abc.abc"))
                    }
                });

                string nonceExpired = (DateTime.UtcNow-TimeSpan.FromDays(20)).Ticks.ToString(CultureInfo.InvariantCulture) + "." + nonceWithoutTimestamp;
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21324:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireTimeStampInNonce = true },
                    TestId = "Nonce is expired",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        Nonce = nonceExpired,
                        ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Nonce, nonceExpired))
                    }
                });

                string nonceMaxTicks = Int64.MaxValue.ToString() + "." + nonceWithoutTimestamp;
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21327:", typeof(ArgumentException)),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = false, RequireTimeStampInNonce = true },
                    TestId = "Nonce ticks == Int64.MaxValue",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        Nonce = nonceMaxTicks,
                        ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Nonce, nonceMaxTicks))
                    }
                });

                string nonceMinTicks = Int64.MinValue.ToString() + "." + nonceWithoutTimestamp;
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21326:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = false, RequireTimeStampInNonce = true },
                    TestId = "Nonce ticks == Int64.MinValue",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        Nonce = nonceMinTicks,
                        ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Nonce, nonceMinTicks))
                    }
                });

                string nonceTicksNegative = ((Int64)(-1)).ToString() + "." + nonceWithoutTimestamp;
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21326:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = false, RequireTimeStampInNonce = true },
                    TestId = "Nonce ticks == ((Int64)(-1))",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        Nonce = nonceTicksNegative,
                        ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Nonce, nonceTicksNegative))
                    }
                });

                string nonceTicksZero = ((Int64)(0)).ToString() + "." + nonceWithoutTimestamp;
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX21326:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireNonce = false, RequireTimeStampInNonce = true },
                    TestId = "Nonce ticks ==  ((Int64)(0))",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        Nonce = nonceTicksZero,
                        ValidatedJsonWebToken = CreateValidatedIdToken(new JProperty(JwtRegisteredClaimNames.Nonce, nonceTicksZero))
                    }
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidateAtHashTheoryData))]
        public void ValidateAtHash(OidcProtocolValidatorJsonWebTokenTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateAtHash", theoryData);
            try
            {
                theoryData.ProtocolValidator.PublicValidateAtHash(theoryData.ValidationContext);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData> ValidateAtHashTheoryData
        {
            get
            {
                var jsonWebTokenHandler = new JsonWebTokenHandler();
                var theoryData = new TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData>();

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException(),
                    First = true,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext == null"
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21332:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext.ValidatedJsonWebToken == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext { ProtocolMessage = new OpenIdConnectMessage() }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21333:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext.ProtocolMessage == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext { ValidatedJsonWebToken = CreateValidatedIdToken() }
                });

                var token = Guid.NewGuid().ToString();
                var hashClaimValue256 = IdentityUtilities.CreateHashClaim(token, "SHA256");
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "Jwt.at_hash == hash(access_token)",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage { AccessToken = token },
                        ValidatedJsonWebToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(new JObject() { { "at_hash", hashClaimValue256 } }.ToString(), Default.AsymmetricSigningCredentials))
                    }
                });

                var hashClaimValue512 = IdentityUtilities.CreateHashClaim(token, "SHA512");
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX21348:", typeof(OpenIdConnectProtocolException)),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId ="Jwt.at_hash != hash(access_token) - 256 - 512",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage{ AccessToken = token},
                        ValidatedJsonWebToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(new JObject() { { "at_hash", hashClaimValue512 } }.ToString(), Default.AsymmetricSigningCredentials))
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX21348:", typeof(OpenIdConnectProtocolException)),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "Jwt.at_hash != hash(access_token)",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage { AccessToken = Guid.NewGuid().ToString() },
                        ValidatedJsonWebToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(new JObject() { { "at_hash", hashClaimValue256 } }.ToString(), Default.AsymmetricSigningCredentials))
                    }
                });

                // The test case below cannot be recreated using the Microsoft.IdentityModel.JsonWebTokens library, as it is impossible to add a duplicate property
                // to a JObject.

                //theoryData.Add(new OidcProtocolValidatorTheoryData
                //{
                //    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX21311:"),
                //    ProtocolValidator = new PublicOpenIdConnectProtocolValidator(),
                //    TestId = "multiple at_hash claims",
                //    ValidationContext = new OpenIdConnectProtocolValidationContext()
                //    {
                //        ProtocolMessage = new OpenIdConnectMessage { AccessToken = Guid.NewGuid().ToString() },
                //        ValidatedIdToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(new JObject() { { "at_hash", hashClaimValue256 }, { "at_hash", hashClaimValue256 } }.ToString(), Default.AsymmetricSigningCredentials))
                //    }
                //});

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX21312:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "Jwt.at_hash == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage { AccessToken = Guid.NewGuid().ToString() },
                        ValidatedJsonWebToken = CreateValidatedIdToken()
                    }
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidateStateTheoryData))]
        public void ValidateState(OidcProtocolValidatorJsonWebTokenTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateState", theoryData);
            try
            {
                theoryData.ProtocolValidator.PublicValidateState(theoryData.ValidationContext);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData> ValidateStateTheoryData
        {
            get
            {
                var theoryData = new TheoryData<OidcProtocolValidatorJsonWebTokenTheoryData>();

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    First = true,
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator(),
                    TestId = "validationContext == null"
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX21329:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireState = true },
                    TestId = "validationContext.State == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext { ProtocolMessage = new OpenIdConnectMessage() }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireState = false },
                    TestId = "validationContext.State == null, RequireState == false",
                    ValidationContext = new OpenIdConnectProtocolValidationContext { ProtocolMessage = new OpenIdConnectMessage() }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX21330:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireState = true },
                    TestId = "validationContext.state != null, protocolMessage.state == null",
                    ValidationContext = new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage(),
                        State = Guid.NewGuid().ToString()
                    }
                });

                var state = Guid.NewGuid().ToString();
                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireState = true },
                    TestId = "validationContext.state == protocolMessage.state",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                    {
                        State = state,
                        ProtocolMessage = new OpenIdConnectMessage { State = state }
                    }
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX21331:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireState = true },
                    TestId = "validationContext.state != protocolMessage.state, RequireState = true",
                    ValidationContext = new OpenIdConnectProtocolValidationContext()
                    {
                        State = Guid.NewGuid().ToString(),
                        ProtocolMessage = new OpenIdConnectMessage { State = Guid.NewGuid().ToString() }
                    },
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireStateValidation = false },
                    TestId = "validationContext.state != protocolMessage.state, RequireStateValidation = false",
                    ValidationContext =  new OpenIdConnectProtocolValidationContext()
                    {
                        State = Guid.NewGuid().ToString(),
                        ProtocolMessage = new OpenIdConnectMessage { State = Guid.NewGuid().ToString() },
                    },
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireState = false },
                    TestId = "validationContext.state == null, protocolMessage.state == null, RequireState = false",
                    ValidationContext =  new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage(),
                    },
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX21330:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireState = false },
                    TestId = "validationContext.state != null, protocolMessage.state == null, RequireState = false",
                    ValidationContext =  new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage(),
                        State = Guid.NewGuid().ToString()
                    },
                });

                theoryData.Add(new OidcProtocolValidatorJsonWebTokenTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX21329:"),
                    ProtocolValidator = new PublicOpenIdConnectJsonWebTokenProtocolValidator { RequireState = false },
                    TestId = "validationContext.state == null, protocolMessage.state != null, RequireState = false",
                    ValidationContext =  new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage { State = Guid.NewGuid().ToString() }
                    },
                });

                return theoryData;
            }
        }

        [Theory]
        [InlineData(SecurityAlgorithms.EcdsaSha256, "SHA256", true)]
        [InlineData(SecurityAlgorithms.EcdsaSha256Signature, "SHA256", true)]
        [InlineData(SecurityAlgorithms.HmacSha256, "SHA256", true)]
        [InlineData(SecurityAlgorithms.RsaSha256, "SHA256", true)]
        [InlineData(SecurityAlgorithms.RsaSha256Signature, "SHA256", true)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha256, "SHA256", true)]
        [InlineData(SecurityAlgorithms.EcdsaSha384, "SHA384", true)]
        [InlineData(SecurityAlgorithms.EcdsaSha384Signature, "SHA384", true)]
        [InlineData(SecurityAlgorithms.HmacSha384, "SHA384", true)]
        [InlineData(SecurityAlgorithms.RsaSha384, "SHA384", true)]
        [InlineData(SecurityAlgorithms.RsaSha384Signature, "SHA384", true)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha384, "SHA384", true)]
        [InlineData(SecurityAlgorithms.EcdsaSha512, "SHA512", true)]
        [InlineData(SecurityAlgorithms.EcdsaSha512Signature, "SHA512", true)]
        [InlineData(SecurityAlgorithms.HmacSha512, "SHA512", true)]
        [InlineData(SecurityAlgorithms.RsaSha512, "SHA512", true)]
        [InlineData(SecurityAlgorithms.RsaSha512Signature, "SHA512", true)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha512, "SHA512", true)]
        [InlineData(SecurityAlgorithms.ExclusiveC14nWithComments, "SHA512", false)]
        [InlineData(SecurityAlgorithms.Aes128KeyWrap, "SHA512", false)]
        public void DefaultAlgorithmMapTest(string algorithm, string expectedHash, bool shouldFind)
        {
            var protocolValidator = new OpenIdConnectProtocolValidator();
            string hashFound;
            Assert.True(protocolValidator.HashAlgorithmMap.TryGetValue(algorithm, out hashFound) == shouldFind);
            if (shouldFind)
                Assert.Equal(hashFound, expectedHash);
        }

        [Theory, MemberData(nameof(HashAlgorithmExtensibilityTheoryData))]
        public void HashAlgorithmExtensibility(OpenIdConnectProtocolValidator protocolValidator, string alg, Type algorithmType, ExpectedException ee)
        {
            ee.Verbose = false;
            try
            {
                var hash = protocolValidator.GetHashAlgorithm(alg);
                ee.ProcessNoException();
                Assert.True(hash.GetType() == algorithmType, string.Format(CultureInfo.InvariantCulture, "hash.GetType() != algorithmType: '{0}' : '{1}'", hash.GetType(), algorithmType));
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<OpenIdConnectProtocolValidator, string, Type, ExpectedException> HashAlgorithmExtensibilityTheoryData
        {
            get
            {
                var theoryData = new TheoryData<OpenIdConnectProtocolValidator, string, Type, ExpectedException>();

                // CustomCryptoProviderFactory understands this 'hash' algorithm
                var customHashAlgorithm = new CustomHashAlgorithm();
                var customCryptoProviderFactory = new CustomCryptoProviderFactory()
                {
                    HashAlgorithm = customHashAlgorithm
                };

                var validator = new OpenIdConnectProtocolValidator()
                {
                    CryptoProviderFactory = customCryptoProviderFactory
                };

                theoryData.Add(validator, SecurityAlgorithms.ExclusiveC14nWithComments, customHashAlgorithm.GetType(), ExpectedException.NoExceptionExpected);

                // Default CryptoProviderFactory faults on this 'hash' algorithm
                validator = new OpenIdConnectProtocolValidator()
                {
                    CryptoProviderFactory = new CryptoProviderFactory()
                };

                theoryData.Add(validator, SecurityAlgorithms.ExclusiveC14nWithComments, customHashAlgorithm.GetType(), new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21301:", typeof(NotSupportedException)));

                // Adjust mapping table, and Default CryptoProviderFactory will find 'hash' algorithm
                var sha2 = SHA256.Create();
                validator = new OpenIdConnectProtocolValidator();
                validator.HashAlgorithmMap[SecurityAlgorithms.ExclusiveC14nWithComments] = SecurityAlgorithms.Sha256;
                theoryData.Add(validator, SecurityAlgorithms.ExclusiveC14nWithComments, sha2.GetType(), ExpectedException.NoExceptionExpected);

                // Support a single hash algorithm, add CryptoProvider that supports hash algorithm
                var cryptoProvider = new CustomCryptoProvider()
                {
                    HashAlgorithm = customHashAlgorithm,
                    IsSupportedResult = true
                };

                cryptoProvider.AdditionalHashAlgorithms.Add(SecurityAlgorithms.ExclusiveC14nWithComments);

                validator = new OpenIdConnectProtocolValidator()
                {
                    CryptoProviderFactory = new CryptoProviderFactory()
                };

                validator.CryptoProviderFactory.CustomCryptoProvider = cryptoProvider;
                theoryData.Add(validator, SecurityAlgorithms.ExclusiveC14nWithComments, customHashAlgorithm.GetType(), ExpectedException.NoExceptionExpected);

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(GetHashAlgorithmTheoryData))]
        public void GetHashAlgorithm(OpenIdConnectProtocolValidator protocolValidator, string alg, Type algorithmType, ExpectedException ee)
        {
            ee.Verbose = false;
            try
            {
                var hash = protocolValidator.GetHashAlgorithm(alg);
                ee.ProcessNoException();
                Assert.True(hash.GetType() == algorithmType);
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<OpenIdConnectProtocolValidator, string, Type, ExpectedException> GetHashAlgorithmTheoryData
        {
            get
            {
                var validator = new OpenIdConnectProtocolValidator();
                var sha2 = SHA256.Create();
                var sha3 = SHA384.Create();
                var sha5 = SHA512.Create();

                return new TheoryData<OpenIdConnectProtocolValidator, string, Type, ExpectedException>
                {
                    {validator, SecurityAlgorithms.EcdsaSha256, sha2.GetType(), ExpectedException.NoExceptionExpected },
                    {validator, SecurityAlgorithms.EcdsaSha256Signature, sha2.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.HmacSha256, sha2.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSha256, sha2.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSha256Signature, sha2.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSsaPssSha256, sha2.GetType(), ExpectedException.NoExceptionExpected},

                    {validator, SecurityAlgorithms.EcdsaSha384, sha3.GetType(), ExpectedException.NoExceptionExpected },
                    {validator, SecurityAlgorithms.HmacSha384, sha3.GetType(), ExpectedException.NoExceptionExpected },
                    {validator, SecurityAlgorithms.RsaSha384, sha3.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSsaPssSha384, sha3.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSha384Signature, sha3.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.EcdsaSha384Signature, sha3.GetType(), ExpectedException.NoExceptionExpected},

                    {validator, SecurityAlgorithms.RsaSha512Signature, sha5.GetType(), ExpectedException.NoExceptionExpected },
                    {validator, SecurityAlgorithms.RsaSsaPssSha512, sha5.GetType(), ExpectedException.NoExceptionExpected },
                    {validator, SecurityAlgorithms.EcdsaSha512, sha5.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.EcdsaSha512Signature, sha5.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.HmacSha512, sha5.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSha512, sha5.GetType(), ExpectedException.NoExceptionExpected},

                    {validator, SecurityAlgorithms.ExclusiveC14nWithComments, sha5.GetType(), new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX21301:", typeof(NotSupportedException))}
                };
            }
        }
    }

    public class OidcProtocolValidatorJsonWebTokenTheoryData : TheoryDataBase
    {
        public JsonWebToken JsonWebToken { get; set; }

        public OpenIdConnectProtocolValidationContext ValidationContext { get; set; }

        public PublicOpenIdConnectJsonWebTokenProtocolValidator ProtocolValidator { get; set; } = new PublicOpenIdConnectJsonWebTokenProtocolValidator();
    }

    public class PublicOpenIdConnectJsonWebTokenProtocolValidator : OpenIdConnectProtocolValidator
    {
        public void PublicValidateIdToken(OpenIdConnectProtocolValidationContext context)
        {
            base.ValidateIdToken(context);
        }

        public void PublicValidateCHash(OpenIdConnectProtocolValidationContext context)
        {
            base.ValidateCHash(context);
        }

        public void PublicValidateAtHash(OpenIdConnectProtocolValidationContext context)
        {
            base.ValidateAtHash(context);
        }

        public void PublicValidateNonce(OpenIdConnectProtocolValidationContext context)
        {
            base.ValidateNonce(context);
        }

        public void PublicValidateState(OpenIdConnectProtocolValidationContext context)
        {
            base.ValidateState(context);
        }

        public void SetHashAlgorithmMap(Dictionary<string, string> hashAlgorithmMap)
        {
            HashAlgorithmMap.Clear();
            foreach (var key in hashAlgorithmMap.Keys)
                HashAlgorithmMap.Add(key, hashAlgorithmMap[key]);
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
