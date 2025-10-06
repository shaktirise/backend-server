param($path)
(Get-Content $path) -replace '^pick 8459076d3aa498d0f4b65bb84668a1ac4af36c36', 'edit 8459076d3aa498d0f4b65bb84668a1ac4af36c36' | Set-Content $path
