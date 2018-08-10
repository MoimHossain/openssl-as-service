
#region using Directives
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SuperNova.Security.Cryptography.CryptographySupports;
#endregion

namespace SuperNova.Security.Cryptography.Controllers
{
    /// <summary>
    /// The Open SSL API
    /// </summary>
    [Produces("application/json")]
    [Route("api/OpenSsl")]
    public class OpenSslController : Controller
    {
        /// <summary>
        /// Converts PEM file to DER
        /// </summary>
        /// <param name="payload">The payload containing the data as string</param>
        /// <returns>String representation</returns>
        [HttpPost("ConvertToPEM")]
        public async Task<IActionResult> ConvertToPem([FromBody] FormatConversionRequestPayload payload)
        {
            var convertedData = await CertificateManager.ConvertToPemAsync(payload);

            return new JsonResult(new { Text = convertedData });
        }

        /// <summary>
        /// Convert a DER file (.crt .cer .der) to PEM
        /// </summary>
        /// <param name="payload">The payload containing the data as string</param>
        /// <returns>String representation</returns>
        [HttpPost("ConvertToDER")]
        public async Task<IActionResult> ConvertToDer([FromBody] FormatConversionRequestPayload payload)
        {
            var convertedData = await CertificateManager.ConvertPemToDerAsync(payload);

            return new JsonResult(new { Text = convertedData });
        }

        /// <summary>
        /// Creates a new CSR
        /// </summary>
        /// <param name="payload">Payload info</param>
        /// <returns>The CSR with private key</returns>
        [HttpPost("CSR")]
        public async Task<IActionResult> Csr([FromBody] CsrRequestPayload payload)
        {
            var response = await CertificateManager.GenerateCSRAsync(payload);
            return new JsonResult(response);
        }

        /// <summary>
        /// Generates PFX file
        /// </summary>
        /// <param name="payload">The payload</param>
        /// <returns>PFX file content</returns>
        [HttpPost]
        [HttpPost("GeneratePFX")]
        public async Task<IActionResult> GeneratePfx([FromBody] ConvertToPfxPayload payload)
        {
            var content = await CertificateManager.GeneratePfxAsync(payload);
            return new JsonResult(new { Text = content });
        }
    }
}
