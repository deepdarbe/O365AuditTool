using System.Text;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class MinimalPdfBuilderTests
{
    [Fact]
    public void BuildSinglePage_EmitsValidHeaderAndSeparateTextLines()
    {
        var bytes = MinimalPdfBuilder.BuildSinglePage(["First line", "Second line"]);
        var pdf = Encoding.ASCII.GetString(bytes);

        Assert.StartsWith("%PDF-1.4", pdf);
        Assert.Contains("(First line) Tj T* (Second line) Tj", pdf);
        Assert.EndsWith("%%EOF" + Environment.NewLine, pdf);
    }
}
