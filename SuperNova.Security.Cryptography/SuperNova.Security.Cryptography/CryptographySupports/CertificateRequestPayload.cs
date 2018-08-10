
#region Using directives
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
#endregion

namespace SuperNova.Security.Cryptography.CryptographySupports
{
    /// <summary>
    /// The payload for PFX generation
    /// </summary>
    /// <remarks>
    ///  openssl pkcs12 -export -out certificate.pfx -inkey privateKey.key -in certificate.crt -certfile CACert.crt
    /// </remarks>
    public class ConvertToPfxPayload
    {
        /// <summary>
        /// Private key
        /// </summary>
        public string PrivateKey { get; set; }
        /// <summary>
        /// Certificate data
        /// </summary>
        public string CertifcateData { get; set; }
        /// <summary>
        /// Authority data
        /// </summary>
        public string CertificateAuthorityData { get; set; }
    }

    /// <summary>
    /// CSR request payload
    /// </summary>
    public class CsrRequestPayload
    {
        /// <summary>
        /// Country
        /// </summary>
        public string Country { get; set; }
        public string State { get; set; }
        public string Location { get; set; }
        public string Organization { get; set; }
        public string OrganizationalUnit { get; set; }
        public string CommonName { get; set; }
    }

    /// <summary>
    /// CSR response
    /// </summary>
    public class CsrResponse
    {
        public string CsrText { get; set; }
        public string Logs { get; set; }
    }

    /// <summary>
    /// Payload to convert a file to another
    /// </summary>
    public class FormatConversionRequestPayload
    {
        /// <summary>
        /// Input file format
        /// </summary>
        [JsonConverter(typeof(StringEnumConverter))]
        public CertificateFormats InputFormat { get; set; }

        /// <summary>
        /// The content
        /// </summary>
        public string Base64FileContent { get; set; }
    }

    /// <summary>
    /// Common certificate file types
    /// </summary>
    [Serializable]
    public enum CertificateFormats
    {
        /// <summary>
        ///  Privacy Enhanced Mail (PEM) file
        /// </summary>
        Pem,
        /// <summary>
        /// Cert files
        /// </summary>
        Cer,

        /// <summary>
        /// DER file
        /// </summary>
        Der,

        /// <summary>
        /// CRT file
        /// </summary>
        Crt
    }
}
