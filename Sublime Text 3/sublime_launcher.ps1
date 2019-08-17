$numOfArgs = $args.Length - 1
$argumentsPassed = 0
$res = ""
for ($i=0; $i -le $numOfArgs; $i++)
{
    write-host "folder: $($args[$i])"
    if ($args[$i] -eq "-z") { i++ }
    else {
        if ($argumentsPassed -ne 0) {
            $res += " "
        }
        $argumentsPassed = 1
        $res += $args[$i]
    }
}
$cmdArgList = @(
    $res
)
$cmdPath = "$PSScriptRoot\sublime_text.exe"
& $cmdPath $cmdArgList