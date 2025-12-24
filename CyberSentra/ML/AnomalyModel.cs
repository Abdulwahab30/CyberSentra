using Microsoft.ML;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CyberSentra.ML
{
    public static class AnomalyModel
    {
        private static readonly MLContext _ml = new(seed: 1);

        /// <summary>
        /// Normalize BOTH baseline and target rows using min/max learned ONLY from baseline.
        /// This keeps scoring consistent across runs and avoids target distribution shifting the scale.
        /// </summary>
        public static void NormalizeUsingReference(List<UserFeatureRow> baseline, List<UserFeatureRow> target)
        {
            if (baseline == null || baseline.Count == 0) return;
            if (target == null) target = new List<UserFeatureRow>();

            int dims = baseline[0].Features.Length;

            // Guard: ensure all rows have same dims
            if (baseline.Any(r => r.Features == null || r.Features.Length != dims) ||
                target.Any(r => r.Features == null || r.Features.Length != dims))
                return;

            var min = new float[dims];
            var max = new float[dims];

            for (int j = 0; j < dims; j++)
            {
                min[j] = float.MaxValue;
                max[j] = float.MinValue;
            }

            foreach (var r in baseline)
            {
                for (int j = 0; j < dims; j++)
                {
                    min[j] = Math.Min(min[j], r.Features[j]);
                    max[j] = Math.Max(max[j], r.Features[j]);
                }
            }

            void norm(List<UserFeatureRow> rows)
            {
                foreach (var r in rows)
                {
                    for (int j = 0; j < dims; j++)
                    {
                        var denom = max[j] - min[j];
                        r.Features[j] = denom < 1e-6 ? 0f : (r.Features[j] - min[j]) / denom;
                    }
                }
            }

            norm(baseline);
            norm(target);
        }

        /// <summary>
        /// Train on baseline rows and score target rows. Flags anomalies using a baseline-derived threshold
        /// (percentile of baseline scores). This is more stable than z-scoring within the target window.
        /// </summary>
        public static List<UserAnomaly> TrainBaselineScoreTarget(
            List<UserFeatureRow> baselineRows,
            List<UserFeatureRow> targetRows,
            double baselinePercentileThreshold = 0.99)
        {
            if (baselineRows == null) baselineRows = new List<UserFeatureRow>();
            if (targetRows == null) targetRows = new List<UserFeatureRow>();

            if (baselineRows.Count < 10 || targetRows.Count == 0)
            {
                return targetRows.Select(r => new UserAnomaly
                {
                    User = r.User,
                    Score = 0f,
                    IsAnomaly = false
                }).ToList();
            }

            // ✅ Normalize using baseline distribution
            NormalizeUsingReference(baselineRows, targetRows);

            var baselineData = _ml.Data.LoadFromEnumerable(baselineRows);
            var targetData = _ml.Data.LoadFromEnumerable(targetRows);

            var pipeline = _ml.AnomalyDetection.Trainers.RandomizedPca(
                featureColumnName: nameof(UserFeatureRow.Features),
                rank: 3,
                ensureZeroMean: true
            );

            var model = pipeline.Fit(baselineData);

            // --- Score baseline (for threshold) ---
            var baselineTransformed = model.Transform(baselineData);
            var baselinePreds = _ml.Data.CreateEnumerable<PcaPrediction>(baselineTransformed, reuseRowObject: false)
                .Select(p => SanitizeScore(p.Score))
                .ToList();

            // Baseline-derived threshold (stable across different target windows)
            var threshold = Percentile(baselinePreds, baselinePercentileThreshold);

            // --- Score target ---
            var targetTransformed = model.Transform(targetData);
            var targetPreds = _ml.Data.CreateEnumerable<PcaPrediction>(targetTransformed, reuseRowObject: false).ToList();

            var scored = targetRows.Zip(targetPreds, (r, p) => new UserAnomaly
            {
                User = r.User,
                Score = SanitizeScore(p.Score),
                IsAnomaly = false
            }).ToList();

            foreach (var s in scored)
                s.IsAnomaly = s.Score > threshold;

            // fallback: mark top score if nothing flagged (keeps UI interesting)
            if (!scored.Any(x => x.IsAnomaly) && scored.Count >= 3)
                scored.OrderByDescending(x => x.Score).First().IsAnomaly = true;

            return scored.OrderByDescending(x => x.Score).ToList();
        }

        /// <summary>
        /// Backward-compatible alias for older call sites.
        /// </summary>
        public static List<UserAnomaly> TrainOnBaselineScoreTarget(
            List<UserFeatureRow> baselineRows,
            List<UserFeatureRow> targetRows)
        {
            return TrainBaselineScoreTarget(baselineRows, targetRows, baselinePercentileThreshold: 0.99);
        }

        private static float SanitizeScore(float score)
        {
            if (float.IsNaN(score) || float.IsInfinity(score)) return 0f;
            // RandomizedPca scores can occasionally be negative; keep as-is unless you want abs()
            return score;
        }

        /// <summary>
        /// Percentile helper for baseline score thresholding.
        /// p is in [0..1], e.g. 0.99 = 99th percentile.
        /// </summary>
        private static float Percentile(List<float> values, double p)
        {
            if (values == null || values.Count == 0) return 0f;

            // Clamp p
            if (p < 0) p = 0;
            if (p > 1) p = 1;

            values.Sort();
            var idx = (int)Math.Round((values.Count - 1) * p);
            idx = Math.Clamp(idx, 0, values.Count - 1);
            return values[idx];
        }
    }
}
