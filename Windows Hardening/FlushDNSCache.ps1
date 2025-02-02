Write-Warning "Flushing DNS Cache"
ipconfig /flushdns
# finding hosts
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
attrib +r +s C:\WINDOWS\system32\drivers\etc\hosts