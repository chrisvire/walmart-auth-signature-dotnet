// --------------------------------------------------------------------------------------------------------------------
// <copyright file="SignatureTests.cs" company="Hubbard Consulting">
//   Copyright (c) Chris Hubbard. All rights reserved.
// </copyright>
// <summary>
//   Defines the SignatureTests type.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

// ReSharper disable StyleCop.SA1600
namespace Walmart.Auth.Tests
{
    using System;
    using System.Diagnostics.CodeAnalysis;

    using Xunit;
    using Xunit.Abstractions;
    using Xunit.Sdk;

    /// <summary>
    /// The Signature tests.
    /// </summary>
    [SuppressMessage("ReSharper", "StyleCop.SA1600")]
    public class SignatureTests
    {
        private const string RequestMethod = "GET";
        private const string ConsumerId = "hw30cqp3-35fi-1bi0-3312-hw9fgm30d2p4";
        private const string PrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKzXEfCYdnBNkKAwVbCpg/tR40WixoZtiuEviSEi4+LdnYAAPy57Qw6+9eqJGTh9iCB2wP/I8lWh5TZ49Hq/chjTCPeJiOqi6bvX1xzyBlSq2ElSY3iEVKeVoQG/5f9MYQLEj5/vfTWSNASsMwnNeBbbHcV1S1aY9tOsXCzRuxapAgMBAAECgYBjkM1j1OA9l2Ed9loWl8BQ8X5D6h4E6Gudhx2uugOe9904FGxRIW6iuvy869dchGv7j41ki+SV0dpRw+HKKCjYE6STKpe0YwIm/tml54aNDQ0vQvF8JWILca1a7v3Go6chf3Ib6JPs6KVsUuNo+Yd+jKR9GAKgnDeXS6NZlTBUAQJBANex815VAySumJ/n8xR+h/dZ2V5qGj6wu3Gsdw6eNYKQn3I8AGQw8N4yzDUoFnrQxqDmP3LOyr3/zgOMNTdszIECQQDNIxiZOVl3/Sjyxy9WHMk5qNfSf5iODynv1OlTG+eWao0Wj/NdfLb4pwxRsf4XZFZ1SQNkbNne7+tEO8FTG1YpAkAwNMY2g/ty3E6iFl3ea7UJlBwfnMkGz8rkye3F55f/+UCZcE2KFuIOVv4Kt03m3vg1h6AQkaUAN8acRl6yZ2+BAkEAke2eiRmYANiR8asqjGqr5x2qcm8ceiplXdwrI1kddQ5VUbCTonSewOIszEz/gWp6arLG/ADHOGWaCo8rptAyiQJACXd1ddXUAKs6x3l752tSH8dOde8nDBgF86NGvgUnBiAPPTmJHuhWrmOZmNaB68PsltEiiFwWByGFV+ld9VKmKg==";

        [Fact]
        public void Signature_ParameterConstructor_Constructs()
        {
            var s = new Signature("consumerId", "privateKey", "requestUrl", "requestMethod");

            Assert.Equal(s.ConsumerId, "consumerId");
            Assert.Equal(s.PrivateKey, "privateKey");
            Assert.Equal(s.RequestUrl, "requestUrl");
            Assert.Equal(s.RequestMethod, "requestMethod");
        }

        [Fact]
        public void Signature_DefaultConstructor_Initializes()
        {
            var s = new Signature
            {
                ConsumerId = "consumerId",
                PrivateKey = "privateKey",
                RequestMethod = "requestMethod",
                RequestUrl = "requestUrl"
            };

            Assert.Equal(s.ConsumerId, "consumerId");
            Assert.Equal(s.PrivateKey, "privateKey");
            Assert.Equal(s.RequestUrl, "requestUrl");
            Assert.Equal(s.RequestMethod, "requestMethod");
        }

        [Theory]
        [InlineData("1462475614410", "https://marketplace.stg.walmartapis.com/v2/feeds?offset=0&limit=1", "IIeNSuFsBGpEQE7OWcprahLC8mk54ljlMFrKdRP2zo2Kil7t1knhb4+WmNq6sg1zZSOo9IjKwtu1eIgqM5Isf8UvcEQYV44ighfDBOLkDmqvc/BJRm6erZ5A/n5gbhIssnv8CtuQvQUdLTw0wAG0sW48CQW8CDTCaxlu2LaCCyw=")]
        [InlineData("1462482229078", "https://marketplace.stg.walmartapis.com/v2/orders?createdStartDate=2015-01-03T05%3A00%3A00Z&offset=0&limit=5", "IIpHJY7wFNV61GA/bx/4A/lzOj7uhB/JodndEQl8wpAVzcfCfD5ovrYclQG3cR3Al9KSLCT3leU5Ug0ikqyp+bI757E3D3zhzzCOyDMpG6mnhcKW/WjTBZIe5KLd2D/oN4c9Eu6mTudd/w6/VKUDB9qxHIGHMoKCWRt2udDZn48=")]
        [InlineData("1462476258197", "https://marketplace.stg.walmartapis.com/v2/items?offset=0&limit=5","GmuOrPQ67wuVje8FYtLqq5Li2/BehKsITW/8CNMNuwI/j0jm0Y6Hbj4zyp963/UYPAUWJUweaMoyw6gHnOnxXV3A/u9oeh19Z4jfTD19w0YKCCSp5dX8RdiktIAYjpITdz8Tnif3McPqtddWLdjz9MjtIZUnGoTCGNWFYlJuc6Y=")]
        public void Signature_GetSignature_MatchExpected(string timestamp, string requestUrl, string expectedSignature)
        {

            var s = new Signature(ConsumerId, PrivateKey, requestUrl, RequestMethod);
            var signature = s.GetSignature(timestamp);
            Assert.Equal(timestamp, s.TimeStamp);
            Assert.Equal(expectedSignature, signature);
        }

        [Fact]
        public void Signature_GetSignature_CorrectLength()
        {
            var requestUrl = "https://marketplace.stg.walmartapis.com/v2/items?offset=0&limit=5";
            var s = new Signature(ConsumerId, PrivateKey, requestUrl, RequestMethod);
            var signature = s.GetSignature(null);
            Assert.Equal(172, signature.Length);
        }

        [Fact]
        public void Signature_InvalidParameters_Exception()
        {
            var consumerId = "test";
            var privateKey = "test";
            var requestUrl = "test";
            var requestMethod = "test";

            var s = new Signature(consumerId, privateKey, requestUrl, requestMethod);
            Exception ex = Assert.Throws<Exception>(() => s.GetSignature(null));
            Assert.Equal("Unable to load private key", ex.Message);
        }
    }
}
