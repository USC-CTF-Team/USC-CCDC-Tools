$taskSchedulerRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
    $tasks = Get-ChildItem -Path $taskSchedulerRegPath -Recurse
    $hiddenTasks = @()
    
    foreach ($task in $tasks) {
        if (-not $task.Property -contains "Id") {
            continue
        }
        try {
            $taskProperties = Get-ItemProperty -Path $task.PSPath
            if (-not $taskProperties.PSObject.Properties.Name -contains "SD") {
                $hiddenTasks += $task.PSChildName
            }
            if ($taskProperties.PSObject.Properties.Name -contains "Index" -and $taskProperties."Index" -eq 0) {
                $hiddenTasks += $task.PSChildName
            }
        } catch {
            Write-Host "Error encountered processing task: $($task.PSChildName). Error: $_"
        }
    }
    
    # Display the results
    if ($hiddenTasks.Count -gt 0) {
        Write-Host "Hidden tasks detected:"
        $hiddenTasks | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "No hidden tasks detected."
    }
