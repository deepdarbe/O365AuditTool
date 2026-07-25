using System.Text.Json;
using O365AuditTool.Models;
using Xunit;

namespace O365AuditTool.Tests;

public class CollectorPayloadCompatibilityTests
{
    [Fact]
    public void Deserialize_V1PayloadWithoutLegacyFiles_UsesEmptyCollection()
    {
        var payload = JsonSerializer.Deserialize<CollectorPayload>(
            """
            {
              "schemaVersion": "1.0",
              "device": { "hostname": "PC01" },
              "storage": {},
              "office": {},
              "profiles": [],
              "mailAccounts": [],
              "pstFiles": [],
              "scanMeta": {},
              "errors": []
            }
            """);

        Assert.NotNull(payload);
        Assert.Empty(payload.LegacyFiles);
        Assert.Equal("1.0", payload.SchemaVersion);
    }
}
