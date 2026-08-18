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

    [Fact]
    public void Deserialize_V1PayloadWithoutNewProfileFields_UsesBackwardCompatibleDefaults()
    {
        var payload = JsonSerializer.Deserialize<CollectorPayload>(
            """
            {
              "schemaVersion": "1.1",
              "device": { "hostname": "PC01" },
              "storage": {},
              "office": {
                "runningProcesses": [
                  { "processName": "OUTLOOK", "pid": 42, "isRunning": true }
                ]
              },
              "profiles": [
                { "sid": "S-1-5-21-1-2-3-1001", "profileName": "Outlook" }
              ],
              "mailAccounts": [],
              "pstFiles": [
                { "sid": "S-1-5-21-1-2-3-1001", "path": "C:\\mail.pst" }
              ],
              "scanMeta": {},
              "errors": []
            }
            """);

        var profile = Assert.Single(Assert.IsType<CollectorPayload>(payload).Profiles);
        Assert.Null(profile.ProfilePath);
        Assert.Null(profile.UserName);
        Assert.False(profile.Loaded);
        Assert.Null(Assert.Single(payload.Office.RunningProcesses).Owner);
        Assert.Null(Assert.Single(payload.PstFiles).ProfileName);
    }

    [Fact]
    public void Deserialize_V12Payload_ReadsProfilePstAndProcessMetadata()
    {
        var payload = JsonSerializer.Deserialize<CollectorPayload>(
            """
            {
              "schemaVersion": "1.2",
              "device": { "hostname": "PC01" },
              "storage": {},
              "office": {
                "runningProcesses": [
                  {
                    "processName": "OUTLOOK",
                    "pid": 42,
                    "isRunning": true,
                    "owner": "CONTOSO\\ada",
                    "sessionId": 3
                  }
                ]
              },
              "profiles": [
                {
                  "sid": "S-1-12-1-1-2-3-4",
                  "profileName": "M365",
                  "profilePath": "C:\\Users\\Ada",
                  "userName": "AzureAD\\ada",
                  "loaded": true
                }
              ],
              "mailAccounts": [],
              "pstFiles": [
                {
                  "sid": "S-1-12-1-1-2-3-4",
                  "profileName": "M365",
                  "path": "C:\\mail.pst"
                }
              ],
              "scanMeta": {},
              "errors": []
            }
            """);

        var result = Assert.IsType<CollectorPayload>(payload);
        var profile = Assert.Single(result.Profiles);
        Assert.Equal(@"C:\Users\Ada", profile.ProfilePath);
        Assert.Equal(@"AzureAD\ada", profile.UserName);
        Assert.True(profile.Loaded);
        Assert.Equal("M365", Assert.Single(result.PstFiles).ProfileName);
        var process = Assert.Single(result.Office.RunningProcesses);
        Assert.Equal(@"CONTOSO\ada", process.Owner);
        Assert.Equal(3, process.SessionId);
    }

    [Fact]
    public void Deserialize_V13Payload_ReadsOfficeStorageAndInteractiveUserMetadata()
    {
        var payload = JsonSerializer.Deserialize<CollectorPayload>(
            """
            {
              "schemaVersion": "1.3",
              "device": {
                "hostname": "PC01",
                "lastLoggedOnUser": "CONTOSO\\ada",
                "currentLoggedOnUser": "CONTOSO\\ada"
              },
              "storage": {
                "disks": [
                  { "model": "Example", "interfaceType": "NVMe", "busType": "NVMe", "mediaType": "SSD" }
                ]
              },
              "office": {
                "installedProducts": [
                  {
                    "name": "Microsoft Office Click-to-Run",
                    "version": "16.0.19029.20136",
                    "installType": "ClickToRun",
                    "architecture": "x64",
                    "updateChannel": "Current",
                    "productIds": "O365ProPlusRetail",
                    "updatesEnabled": true
                  }
                ]
              }
            }
            """);

        var result = Assert.IsType<CollectorPayload>(payload);
        Assert.Equal(@"CONTOSO\ada", result.Device.CurrentLoggedOnUser);
        var disk = Assert.Single(result.Storage.Disks);
        Assert.Equal("NVMe", disk.BusType);
        Assert.Equal("SSD", disk.MediaType);
        var product = Assert.Single(result.Office.InstalledProducts);
        Assert.Equal("x64", product.Architecture);
        Assert.True(product.UpdatesEnabled);
    }
}
