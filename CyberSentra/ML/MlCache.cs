using System;
using System.Collections.Generic;
using CyberSentra.ML;

namespace CyberSentra
{
    public static class MlCache
    {
        public static DateTime LastRunUtc { get; private set; } = DateTime.MinValue;
        public static List<UserAnomaly> LatestScored { get; private set; } = new();
        public static Dictionary<string, UserFeatureRow> LatestTargetMap { get; private set; } = new();
        public static float[] LatestBaselineMean { get; private set; } = Array.Empty<float>();

        public static void Update(List<UserAnomaly> scored, Dictionary<string, UserFeatureRow> targetMap, float[] baselineMean)
        {
            LatestScored = scored;
            LatestTargetMap = targetMap;
            LatestBaselineMean = baselineMean;
            LastRunUtc = DateTime.UtcNow;
        }
    }
}
