# AntiScreenCap
Inject code "SetWindowDisplayAffinity" to every process which has window. It can't work on wpf app which set AllowsTransparency="True"(e.g. QQ)

"Hide" and "Unhide" hook current windows while "RtlHide" taking a real-time hook. 
