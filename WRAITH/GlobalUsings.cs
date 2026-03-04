// Disambiguate types that conflict when UseWPF + UseWindowsForms are both true.
// WPF wins for all UI types; WinForms types are referenced fully-qualified where needed.
global using Application = System.Windows.Application;
global using Color        = System.Windows.Media.Color;
global using Brushes      = System.Windows.Media.Brushes;
global using MessageBox   = System.Windows.MessageBox;
global using TextBox      = System.Windows.Controls.TextBox;
