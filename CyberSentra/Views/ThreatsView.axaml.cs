using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Threading;
using CyberSentra.ML;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace CyberSentra
{
    public partial class ThreatsView : UserControl, INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        private List<ThreatInfo> _allThreats = new();
        public ObservableCollection<ThreatInfo> Threats { get; } = new();

        public string TotalThreatsText => $"Total threats: {Threats.Count}";

        public string HighSeverityText
        {
            get
            {
                var count = Threats.Count(t => t.Severity.Equals("High", StringComparison.OrdinalIgnoreCase));
                return $"High severity: {count}";
            }
        }

        private string _currentSeverity = "All";
        private string _techniqueFilter = string.Empty;

        private readonly HashSet<string> _notified = new();
        private static string ThreatKey(ThreatInfo t)
        {
            var detailsHash = (t.Details ?? "").GetHashCode();
            return $"{t.Time}|{t.Technique}|{t.Name}|{t.User}|{detailsHash}";
        }

        private async void ShowToast(string title, string message)
        {
            var toast = new Window
            {
                Width = 360,
                Height = 120,
                CanResize = false,
                SystemDecorations = SystemDecorations.None,
                Topmost = true,
                Content = new StackPanel
                {
                    Margin = new Thickness(12),
                    Spacing = 6,
                    Children =
            {
                new TextBlock { Text = title, FontWeight = Avalonia.Media.FontWeight.Bold, FontSize = 14 },
                new TextBlock { Text = message, Opacity = 0.85, TextWrapping = Avalonia.Media.TextWrapping.Wrap }
            }
                }
            };

            // show near top-right of main window
            var owner = TopLevel.GetTopLevel(this) as Window;
            if (owner != null)
            {
                toast.WindowStartupLocation = WindowStartupLocation.Manual;

                int x = (int)(owner.Position.X + owner.Width - toast.Width - 20);
                int y = (int)(owner.Position.Y + 40);

                toast.Position = new PixelPoint(x, y);
                toast.Show(owner);
            }
            else
            {
                toast.Show();
            }

            await Task.Delay(3500);
            toast.Close();
        }



        public ThreatsView()
        {
            InitializeComponent();
            DataContext = this;
            LoadThreatsFromEvents();




        }

        private bool _initialized = false;

        private static float[] ComputeMean(List<UserFeatureRow> rows)
        {
            if (rows.Count == 0) return Array.Empty<float>();

            int d = rows[0].Features.Length;
            var mean = new float[d];

            foreach (var r in rows)
                for (int i = 0; i < d; i++)
                    mean[i] += r.Features[i];

            for (int i = 0; i < d; i++)
                mean[i] /= rows.Count;

            return mean;
        }
        private void LoadThreatsFromEvents()
        {
            var events = EventContext.GetCurrentEvents();
            var ruleThreats = ThreatDetector.GetThreats(events);

            var scored = MlCache.LatestScored;
            var targetMap = MlCache.LatestTargetMap;
            var baselineMean = MlCache.LatestBaselineMean;

            var mlThreats = MlThreatBridge.BuildMlThreats(scored, targetMap, baselineMean);

            _allThreats = ruleThreats
                .Concat(mlThreats)
                .OrderByDescending(t => DateTime.TryParse(t.Time, out var dt) ? dt : DateTime.MinValue)
                .ToList();

            if (!_initialized)
            {
                foreach (var t in _allThreats)
                    _notified.Add(ThreatKey(t));

                _initialized = true;
                ApplyFilter();
                return;
            }


            var newThreats = _allThreats.Where(t => _notified.Add(ThreatKey(t))).Take(3).ToList();
            foreach (var t in newThreats)
                Dispatcher.UIThread.Post(() =>
                {
                    ShowToast($"New threat: {t.Name}",
                              $"{t.User} • {t.Severity} • {t.Technique}");
                });


            ApplyFilter();
        }



        private void ApplyFilter()
        {
            Threats.Clear();

            foreach (var t in _allThreats)
            {
                if (!string.Equals(_currentSeverity, "All", StringComparison.OrdinalIgnoreCase) &&
                    !t.Severity.Equals(_currentSeverity, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!string.IsNullOrWhiteSpace(_techniqueFilter) &&
                    !t.Technique.Contains(_techniqueFilter, StringComparison.OrdinalIgnoreCase))
                    continue;

                Threats.Add(t);
            }

            OnPropertyChanged(nameof(TotalThreatsText));
            OnPropertyChanged(nameof(HighSeverityText));
        }

        private void SeverityCombo_SelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (sender is ComboBox combo && combo.SelectedItem is ComboBoxItem item)
            {
                _currentSeverity = item.Content?.ToString() ?? "All";
                ApplyFilter();
            }
        }

        private void TechniqueSearchBox_KeyUp(object? sender, KeyEventArgs e)
        {
            if (sender is TextBox tb)
            {
                _techniqueFilter = tb.Text ?? string.Empty;
                ApplyFilter();
            }
        }

        private async void ViewThreatDetails_Click(object? sender, RoutedEventArgs e)
        {
            if (sender is not Control c) return;
            if (c.DataContext is not ThreatInfo t) return;

            var tb = new TextBox
            {
                Text = t.Details ?? "",
                IsReadOnly = true,
                AcceptsReturn = true,
                TextWrapping = Avalonia.Media.TextWrapping.Wrap,
               // VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                //HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            };

            var copyBtn = new Button { Content = "Copy", HorizontalAlignment = HorizontalAlignment.Right };
            copyBtn.Click += async (_, __) =>
            {
                var top = TopLevel.GetTopLevel(this);
                if (top?.Clipboard != null)
                    await top.Clipboard.SetTextAsync(tb.Text);
            };

            var panel = new StackPanel { Spacing = 10, Margin = new Thickness(14) };
            panel.Children.Add(new TextBlock { Text = "Threat Details", FontSize = 16, FontWeight = Avalonia.Media.FontWeight.Bold });
            panel.Children.Add(new TextBlock
            {
                Text = $"{t.Time} • {t.Technique} • {t.Tactic} • {t.Severity}",
                Opacity = 0.8,
                FontSize = 12
            });
            panel.Children.Add(copyBtn);
            panel.Children.Add(tb);

            var win = new Window
            {
                Title = "Threat Details",
                Width = 900,
                Height = 520,
                Content = panel
            };

            var owner = TopLevel.GetTopLevel(this) as Window;
            if (owner != null) await win.ShowDialog(owner);
            else win.Show();
        }
    }
}
