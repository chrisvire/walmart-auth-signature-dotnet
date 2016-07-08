using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Walmart.Auth
{
    using System.Globalization;

    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;

    public class Signature
    {
        /// <summary>
        /// The Epoch used by Java for TimeStamps.
        /// </summary>
        private static readonly DateTime Jan1st1970 = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Initializes a new instance of the <see cref="Signature"/> class. 
        /// Default Constructor for Object initializer
        /// </summary>
        public Signature()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Signature"/> class.
        /// </summary>
        /// <param name="consumerId">
        /// The Consumer ID provided by Developer Portal.
        /// </param>
        /// <param name="privateKey">
        /// The Base64 Encoded Private Key provided by Developer Portal.
        /// </param>
        /// <param name="requestUrl">
        /// The URL of API request being made.
        /// </param>
        /// <param name="requestMethod">
        /// The HTTP request method for API call (GET/POST/PUT/DELETE/OPTIONS/PATCH).
        /// </param>
        public Signature(string consumerId, string privateKey, string requestUrl, string requestMethod)
        {
            this.ConsumerId = consumerId;
            this.PrivateKey = privateKey;
            this.RequestUrl = requestUrl;
            this.RequestMethod = requestMethod;
        }

        /// <summary>
        /// Gets or sets Consumer ID provided by Developer Portal
        /// </summary>
        public string ConsumerId { get; set; }

        /// <summary>
        /// Gets or sets Base64 Encoded Private Key provided by Developer Portal
        /// </summary>
        public string PrivateKey { get; set; }

        /// <summary>
        /// Gets or sets URL of API request being made
        /// </summary>
        public string RequestUrl { get; set; }

        /// <summary>
        /// Gets or sets HTTP request method for API call (GET/POST/PUT/DELETE/OPTIONS/PATCH)
        /// </summary>
        public string RequestMethod { get; set; }

        /// <summary>
        /// Gets the time stamp used for the signature.
        /// </summary>
        public string TimeStamp { get; private set; }

        /// <summary>
        /// Get the signature based on the timestamp.  If the timestamp is null, create
        /// a new timestamp.
        /// </summary>
        /// <param name="timeStamp">
        /// The time stamp.
        /// </param>
        /// <returns>
        /// The calculate signature <see cref="string"/>.
        /// </returns>
        public string GetSignature(string timeStamp)
        {
            this.TimeStamp = timeStamp ?? GetTimestampInJavaMillis();

            // Append values into string for signing
            var message = this.ConsumerId + "\n" + this.RequestUrl + "\n" +
                this.RequestMethod.ToUpper() + "\n" + this.TimeStamp + "\n";

            RsaKeyParameters rsaKeyParameter;
            try
            {
                var keyBytes = Convert.FromBase64String(this.PrivateKey);
                var asymmetricKeyParameter = PrivateKeyFactory.CreateKey(keyBytes);
                rsaKeyParameter = (RsaKeyParameters)asymmetricKeyParameter;
            }
            catch (System.Exception)
            {
                throw new Exception("Unable to load private key");
            }

            var signer = SignerUtilities.GetSigner("SHA256withRSA");
            signer.Init(true, rsaKeyParameter);
            var messageBytes = Encoding.UTF8.GetBytes(message);
            signer.BlockUpdate(messageBytes, 0, messageBytes.Length);
            var signed = signer.GenerateSignature();
            var hashed = Convert.ToBase64String(signed);
            return hashed;
        }

        /// <summary>
        /// Get the TimeStamp as a string equivalent to Java System.currentTimeMillis
        /// </summary>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        private static string GetTimestampInJavaMillis()
        {
            var millis = (DateTime.UtcNow - Jan1st1970).TotalMilliseconds;
            return Convert.ToString(Math.Round(millis), CultureInfo.InvariantCulture);
        }
    }
}
