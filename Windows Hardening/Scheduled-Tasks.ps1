# Getting scheduled tasks
Get-ScheduledTask | Select-Object TaskName | Set-Content -Encoding UTF8 .\scheduledTasks.txt
    
# Sorting scheduledTasks.txt
Get-Content .\scheduledTasks.txt | Sort-Object | Get-Unique | Set-Content -Encoding UTF8 .\passthrough.txt
Get-Content .\passthrough.txt | Set-Content -Encoding UTF8 .\scheduledTasks.txt

# Getting Standard Windows info out of scheduledTasks.txt
$lines = Get-Content .\scheduledTasks.txt

for ($i=0; $i -lt $lines.Length; $i++) {
    $lines[$i] = $lines[$i].Substring(11)
    $lines[$i] = $lines[$i].Substring(0, $lines[$i].Length-1)
}

Write-Output $lines | Set-Content .\scheduledTasks.txt

# Get a diff of the two files
Compare-Object (Get-Content .\scheduledTasks.txt) (Get-Content .\scheduledTasksWhitelist.txt) | Where-Object {$_.SideIndicator -eq "<="} 
