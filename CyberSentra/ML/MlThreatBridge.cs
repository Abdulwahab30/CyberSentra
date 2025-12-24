using System;
using System.Collections.Generic;
using System.Linq;
using CyberSentra.ML;

namespace CyberSentra
{
    public static class MlThreatBridge
    {
        public static List<ThreatInfo> BuildMlThreats(
            List<UserAnomaly> scored,
            Dictionary<string, UserFeatureRow> targetRowByUserWindow,
            float[] baselineMean)
        {
            var outList = new List<ThreatInfo>();

            foreach (var a in scored.Where(x => x.IsAnomaly))
            {
                var severity = a.Score >= 0.8 ? "High" : "Medium"; // simple mapping; tune later

                var details = $"ML anomaly score: {a.Score:0.000}\n";

                if (targetRowByUserWindow.TryGetValue(a.User, out var row) &&
                    baselineMean.Length == row.Features.Length)
                {
                    var reasons = BuildReasons(row.Features, baselineMean);
                    details += "\nReasons:\n- " + string.Join("\n- ", reasons);
                }
                else
                {
                    details += "\nReasons: (no feature breakdown available)";
                }

                outList.Add(new ThreatInfo
                {
                    Time = DateTime.Now.ToString("o"), // or extract the hour bucket from a.User
                    User = a.User,
                    Source = "ML",
                    Technique = "ML",
                    Name = "ML: Unusual activity",
                    Tactic = "Anomaly Detection",
                    Severity = severity,
                    Details = details
                });
            }

            return outList;
        }

        private static List<string> BuildReasons(float[] x, float[] mean)
        {
            string[] names =
            {
                "Total events", "Failed logons", "Errors/Failures", "Warnings",
                "Unique processes", "Unique sources",
                "Sysmon Proc Create (EID 1)", "Sysmon Network (EID 3)",
                "LOLBin executions", "Suspicious command lines",
                "Security 4625", "Sysmon File Create (EID 11)"
            };

            var diffs = x.Select((v, i) => new { i, delta = v - mean[i], v })
                         .OrderByDescending(a => a.delta)
                         .Take(3)
                         .ToList();

            var outList = new List<string>();
            foreach (var d in diffs)
            {
                if (d.delta <= 0) continue;
                outList.Add($"{names[d.i]} is higher than baseline (value {d.v:0.###}).");
            }

            if (outList.Count == 0)
                outList.Add("No strong feature deviation from baseline (score-based anomaly).");

            return outList;
        }
    }
}
