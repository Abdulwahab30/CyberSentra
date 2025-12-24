using System;
using System.Collections.Generic;
using System.Linq;

namespace CyberSentra.ML
{
    public static class FeatureBuilder
    {
        // Features (6):
        // 0 TotalEvents
        // 1 FailedLogins
        // 2 Errors/Failures
        // 3 Warnings
        // 4 UniqueProcesses
        // 5 UniqueSources

        private static bool ContainsAny(string haystack, params string[] needles)
        {
            if (string.IsNullOrWhiteSpace(haystack)) return false;

            foreach (var n in needles)
            {
                if (haystack.Contains(n, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public static List<UserFeatureRow> BuildPerUserFeatures(IReadOnlyList<EventRecord> events)
        {
            var grouped = events
                .GroupBy(e =>
                {
                    var u = string.IsNullOrWhiteSpace(e.User) ? "Unknown" : e.User;
                    return u;
                }).Where(g => g.Key != "Unknown");


            var rows = new List<UserFeatureRow>();

            foreach (var g in grouped)
            {
                var user = g.Key;

                int total = g.Count();

                int failed = g.Count(e =>
                    (e.Details ?? "").Contains("failed", StringComparison.OrdinalIgnoreCase));

                int errors = g.Count(e =>
                    (e.Severity ?? "").Equals("Error", StringComparison.OrdinalIgnoreCase) ||
                    (e.Severity ?? "").Contains("Failure", StringComparison.OrdinalIgnoreCase) ||
                    (e.Severity ?? "").Equals("Critical", StringComparison.OrdinalIgnoreCase));

                int warnings = g.Count(e =>
                    (e.Severity ?? "").Equals("Warning", StringComparison.OrdinalIgnoreCase));

                int uniqueProc = g.Select(e => e.Process ?? "")
                                  .Where(x => !string.IsNullOrWhiteSpace(x))
                                  .Distinct().Count();

                int uniqueSrc = g.Select(e => e.Source ?? "")
                                 .Where(x => !string.IsNullOrWhiteSpace(x))
                                 .Distinct().Count();

                rows.Add(new UserFeatureRow
                {
                    User = user,
                    Features = new float[]
                    {
                        total,
                        failed,
                        errors,
                        warnings,
                        uniqueProc,
                        uniqueSrc
                    }
                });
            }

            return rows;
        }
        public static List<UserFeatureRow> BuildPerUserHourlyFeatures(IReadOnlyList<EventRecord> events, int lastHours = 24)
        {
            var now = DateTime.Now;
            var cutoff = now.AddHours(-lastHours);

            // Parse time once
            var parsed = events
                .Select(e => new
                {
                    Event = e,
                    ParsedTime = DateTime.TryParse(e.Time, out var t) ? t : (DateTime?)null
                })
                .Where(x => x.ParsedTime.HasValue && x.ParsedTime.Value >= cutoff)
                .ToList();

            // Group by (User, HourBucket)
            var grouped = parsed.GroupBy(x =>
            {
                var u = string.IsNullOrWhiteSpace(x.Event.User) ? "Unknown" : x.Event.User;
                var t = x.ParsedTime!.Value;
                var bucket = new DateTime(t.Year, t.Month, t.Day, t.Hour, 0, 0);
                return (User: u, Bucket: bucket);
            });
           // .Where(g => g.Key.User != "Unknown");


            var rows = new List<UserFeatureRow>();

            foreach (var g in grouped)
            {
                var user = g.Key.User;
                var evs = g.Select(x => x.Event).ToList();

                int total = evs.Count;
                int failed = evs.Count(e =>
                     e.Type.Equals("Security", StringComparison.OrdinalIgnoreCase) &&
                     e.EventId == 4625);

                int errors = evs.Count(e =>
                    (e.Severity ?? "").Equals("Error", StringComparison.OrdinalIgnoreCase) ||
                    (e.Severity ?? "").Contains("Failure", StringComparison.OrdinalIgnoreCase) ||
                    (e.Severity ?? "").Equals("Critical", StringComparison.OrdinalIgnoreCase));
                int warnings = evs.Count(e => (e.Severity ?? "").Equals("Warning", StringComparison.OrdinalIgnoreCase));

                int uniqueProc = evs.Select(e => e.Process ?? "").Where(x => !string.IsNullOrWhiteSpace(x)).Distinct().Count();
                int uniqueSrc = evs.Select(e => e.Source ?? "").Where(x => !string.IsNullOrWhiteSpace(x)).Distinct().Count();


                int sysmon1 = evs.Count(e => e.Type.Equals("Sysmon", StringComparison.OrdinalIgnoreCase) && e.EventId == 1);
                int sysmon3 = evs.Count(e => e.Type.Equals("Sysmon", StringComparison.OrdinalIgnoreCase) && e.EventId == 3);
                int sysmon11 = evs.Count(e => e.Type.Equals("Sysmon", StringComparison.OrdinalIgnoreCase) && e.EventId == 11);
                int sec4625 = evs.Count(e => e.Type.Equals("Security", StringComparison.OrdinalIgnoreCase) && e.EventId == 4625);

                int lolbin = evs.Count(e =>
                {
                    var img = (e.Image ?? e.Process ?? "").ToLowerInvariant();
                    var cmd = (e.CommandLine ?? e.Details ?? "").ToLowerInvariant();
                    return ContainsAny(img + " " + cmd, "powershell", "pwsh", "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin", "schtasks", "wmic");
                });

                int suspCmd = evs.Count(e =>
                {
                    var cmd = (e.CommandLine ?? e.Details ?? "").ToLowerInvariant();
                    return cmd.Contains("encodedcommand") || cmd.Contains("frombase64string") || cmd.Contains("downloadstring") ||
                           cmd.Contains("executionpolicy bypass") || cmd.Contains(" -w hidden") || cmd.Contains("http://") || cmd.Contains("https://") ||
                           cmd.Contains("--cybersentra-demo");
                });

                rows.Add(new UserFeatureRow
                {
                    User = $"{user} | {g.Key.Bucket:MM-dd HH}:00",
                    Features = new float[]
                    {
                        total, failed, errors, warnings, uniqueProc, uniqueSrc,
                        sysmon1, sysmon3, lolbin, suspCmd, sec4625, sysmon11
                    }
                });
            }

            return rows;
        }

    }
}
