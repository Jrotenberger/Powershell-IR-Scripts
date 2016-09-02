

$text = &[powershell -sta {add-type -a system.windows.forms; [windows.forms.clipboard]::GetText()} | Out-file $dest\MiscInfo_1_clipboard-contents