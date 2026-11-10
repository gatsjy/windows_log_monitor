# Field names of the Windows events the server names (server/app/normalizers/win_templates.py), read from the
# provider manifests of this machine (Get-WinEvent -ListProvider). Read-only: it changes nothing on the machine.
# The committed file (server/tests/fixtures/winevtlog/manifest-templates.json) lets the Linux tests check the names
# and their order for every version of an event - also events this CI cannot raise (domain controller Kerberos
# 4768/4769/4771, domain group membership) - BACKLOG B-45.
#
#   dump_templates.ps1 -Fixture <file> -Update [-Add "Provider:Id,Provider:Id"]   rewrite the file: its events + -Add
#   dump_templates.ps1 -Fixture <file>                                             compare this machine with the file (CI)
#
# -Update keeps the versions this machine does not have (dumped earlier on a newer Windows) and refuses names that
# differ from the file for the same version: a published event version does not change. It also refuses templates
# whose order the manifest cannot give (struct members, count= arrays, length= fields - see Get-Names).
# The compare prints one WLMTEMPLATE line per difference (a new version, other names, a version or provider this
# machine lacks, a template that cannot be read) and a GitHub warning, and exits 0: a new runner image must not fail
# unrelated work. Until the file and the templates are updated the server counts records of an unknown version as
# template_mismatch (ingest quality, B-56). Windows PowerShell 5.1 compatible, English only (AGENTS.md rule 8).
param(
    [Parameter(Mandatory = $true)] [string] $Fixture,
    [switch] $Update,
    [string[]] $Add = @()
)
$ErrorActionPreference = "Stop"
# .NET file calls resolve a relative path against the process directory, not the PowerShell location
$FixturePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Fixture)

function Get-Key($provider, $id, $version) { return "{0}|{1}|{2}" -f $provider, [int]$id, [int]$version }

function Read-Fixture([string] $path) {
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $rows = @()
    foreach ($r in @(([IO.File]::ReadAllText($path) | ConvertFrom-Json).events)) {
        $names = @($r.names | ForEach-Object { [string]$_ })
        $rows += [pscustomobject]@{ provider = [string]$r.provider; id = [int]$r.id; version = [int]$r.version; names = $names; joined = ($names -join ",") }
    }
    return $rows
}

# Field names in template order, or $null when the manifest cannot give the StringInserts order: <struct> members,
# count= arrays (Fluent Bit leaves array values out of StringInserts, so later names would shift) and length= fields
# (Service Control Manager 7031 sends BinaryData but not its __binLength field)
function Get-Names($e) {
    if (-not $e.Template) { return , @() }
    $nodes = @(([xml]$e.Template).DocumentElement.ChildNodes | Where-Object { $_.NodeType -eq [Xml.XmlNodeType]::Element })
    foreach ($n in $nodes) {
        if ($n.LocalName -ne "data" -or $n.GetAttribute("count") -or $n.GetAttribute("length")) { return $null }
    }
    return , @($nodes | ForEach-Object { $_.GetAttribute("name") })
}

function Get-Live($keys) {
    $rows = @{}
    $problems = New-Object System.Collections.ArrayList
    foreach ($group in @($keys | Group-Object provider)) {
        $ids = @($group.Group | ForEach-Object { [int]$_.id })
        try { $events = @((Get-WinEvent -ListProvider $group.Name -ErrorAction Stop).Events) }
        catch { [void]$problems.Add("provider not on this machine: $($group.Name)"); continue }
        foreach ($e in $events) {
            # Classic event IDs carry the qualifiers in the high bits (7045 = 0x40001B85)
            $id = [int]([long]$e.Id -band 0xFFFF)
            if ($ids -notcontains $id) { continue }
            $key = Get-Key $group.Name $id $e.Version
            $names = Get-Names $e
            if ($null -eq $names) { [void]$problems.Add("struct, array or length field, name it by hand: $key"); continue }
            $joined = $names -join ","
            if ($rows.ContainsKey($key) -and $rows[$key].joined -cne $joined) {
                [void]$problems.Add("in the manifest twice with other names: $key"); continue
            }
            $rows[$key] = [pscustomobject]@{ provider = $group.Name; id = $id; version = [int]$e.Version; names = $names; joined = $joined }
        }
        foreach ($id in $ids) {
            if (-not @($rows.Values | Where-Object { $_.provider -eq $group.Name -and $_.id -eq $id }).Count) {
                [void]$problems.Add("no template on this machine: $($group.Name)|$id")
            }
        }
    }
    return @{ rows = $rows; problems = @($problems) }
}

function Format-Fixture($rows, [string] $source) {
    # Ordinal order (provider, id, version) - the same on every machine and culture
    $sorted = New-Object 'System.Collections.Generic.SortedDictionary[string,object]' ([StringComparer]::Ordinal)
    foreach ($r in $rows) {
        $order = "{0}|{1:D5}|{2:D3}" -f $r.provider, $r.id, $r.version
        $sorted[$order] = $r
    }
    # One event version per line keeps the diff readable; names stay an array even with one element
    $lines = foreach ($r in $sorted.Values) {
        $names = ($r.names | ForEach-Object { ConvertTo-Json ([string]$_) }) -join ", "
        '{"provider": ' + (ConvertTo-Json ([string]$r.provider)) + ', "id": ' + $r.id + ', "version": ' + $r.version + ', "names": [' + $names + ']}'
    }
    return '{"source": ' + (ConvertTo-Json $source) + ",`n" + '"events": [' + "`n" + ($lines -join ",`n") + "`n]}`n"
}

$want = @(Read-Fixture $FixturePath)
$keys = @{}
foreach ($r in $want) { $keys["$($r.provider)|$($r.id)"] = [pscustomobject]@{ provider = $r.provider; id = $r.id } }
# powershell -File passes -Add "a,b" as one string: split it here
foreach ($a in @($Add | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    $i = $a.LastIndexOf(":")
    if ($i -lt 1) { throw "-Add takes Provider:Id, not $a" }
    $provider = $a.Substring(0, $i)
    $id = [int]$a.Substring($i + 1)
    $keys["$provider|$id"] = [pscustomobject]@{ provider = $provider; id = $id }
}
if (-not $keys.Count) { throw "$Fixture has no events: give -Add Provider:Id" }
$live = Get-Live @($keys.Values)
$old = @{}
foreach ($r in $want) { $old[(Get-Key $r.provider $r.id $r.version)] = $r }

if ($Update) {
    if ($live.problems.Count) { throw ("Not updated:`n" + ($live.problems -join "`n")) }
    $merged = @{}
    foreach ($k in $old.Keys) { $merged[$k] = $old[$k] }
    foreach ($k in $live.rows.Keys) {
        if ($old.ContainsKey($k) -and $old[$k].joined -cne $live.rows[$k].joined) {
            throw "$k has other names on this machine than in $Fixture - a published event version does not change, check it by hand"
        }
        $merged[$k] = $live.rows[$k]
    }
    $kept = @($old.Keys | Where-Object { -not $live.rows.ContainsKey($_) } | Sort-Object)
    $os = Get-CimInstance Win32_OperatingSystem
    $ubr = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
    $source = "Get-WinEvent -ListProvider on $($os.Caption) $($os.Version).$ubr (tools/ci/dump_templates.ps1)"
    if ($kept.Count) { $source += "; $($kept.Count) versions kept from the previous file (not on that machine)" }
    [IO.File]::WriteAllText($FixturePath, (Format-Fixture @($merged.Values) $source), (New-Object Text.UTF8Encoding $false))
    "wrote $($merged.Count) versions of $($keys.Count) events to $Fixture"
    foreach ($k in $kept) { "kept (not on this machine): $k" }
    exit 0
}

$diff = New-Object System.Collections.ArrayList
foreach ($p in $live.problems) { [void]$diff.Add($p) }
foreach ($k in $live.rows.Keys) {
    if (-not $old.ContainsKey($k)) { [void]$diff.Add("new version $k : $($live.rows[$k].joined)") }
    elseif ($old[$k].joined -cne $live.rows[$k].joined) { [void]$diff.Add("other names $k : $($live.rows[$k].joined) (fixture: $($old[$k].joined))") }
}
foreach ($k in $old.Keys) { if (-not $live.rows.ContainsKey($k)) { [void]$diff.Add("not on this machine $k") } }
foreach ($d in ($diff | Sort-Object)) {
    "WLMTEMPLATE $d"
    if ($env:GITHUB_ACTIONS -eq "true") {
        "::warning title=Windows event templates::$d - update win_templates.py and regenerate the fixture (server/tests/fixtures/winevtlog/README.md)"
    }
}
if (-not $diff.Count) { "templates match the fixture: $($live.rows.Count) versions of $($keys.Count) events" }
exit 0
