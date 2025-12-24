using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberSentra
{
    public class EventRecord
    {
        public string Time { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;      // Security/System/Application/Sysmon
        public string Severity { get; set; } = string.Empty;
        public string User { get; set; } = string.Empty;

        public string Process { get; set; } = string.Empty;   // Provider/Source, not always "process"
        public string Details { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;

        // ✅ NEW (critical)
        public int EventId { get; set; } = 0;

        // ✅ OPTIONAL but highly useful (demo & rules)
        public string Image { get; set; } = string.Empty;         // Sysmon: Image
        public string CommandLine { get; set; } = string.Empty;   // Sysmon: CommandLine
        public string ParentImage { get; set; } = string.Empty;   // Sysmon: ParentImage
        public string DestinationIp { get; set; } = string.Empty; // Sysmon: DestinationIp
        public string DestinationPort { get; set; } = string.Empty;
    }
}

