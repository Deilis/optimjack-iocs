rule HECAVEX_Optimizely_TrackJS_Loader_2026_11
{
    meta:
        description = "Loader injected into Optimizely Web Project JavaScript on 16 November 2026: plain, base64 and inline-fallback forms"
        author = "HECAVEX"
        date = "2026-11-17"
        reference = "https://hecavex.com/en/research/optimizely-supply-chain-track-js/"
        scope = "hunting rule for saved snippets, CDN exports and browser cache; not a production block"
    strings:
        $host_plain = "1688360.cc/track.js" ascii
        $host_b64   = "aHR0cHM6Ly8xNjg4MzYwLmNjL3RyYWNrLmpz" ascii
        $err_pixel  = "px.gif?e=" ascii
        $cb         = "track.js?cb=" ascii
        $ieval      = "(0,eval)(" ascii
        $done       = "DONE=1;boot();" ascii
        $create     = "createElement('script')" ascii
        $cfasync    = "'data-cfasync','false'" ascii
    condition:
        filesize < 3MB and ($host_plain or $host_b64 or ($err_pixel and $cb) or ($ieval and $done) or ($create and $cfasync and $host_b64))
}

rule HECAVEX_Optimizely_TrackJS_Payload_2026_11
{
    meta:
        description = "track.js payload family: rule engine, multi-chain address replacement, card skimmer"
        author = "HECAVEX"
        date = "2026-11-17"
        scope = "hunting rule; matches decoded text, not the reversed-base64 rule bodies of the first build"
    strings:
        $guard_clip = "W._k7 = 1" ascii
        $guard_card = "W._cc = 1" ascii
        $setter     = "getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set" ascii
        $hit        = "/hit.php" ascii
        $card       = "/card.php" ascii
        $dedupe     = "'cc_' + pan + e + c" ascii
        $hook       = "/hook.php" ascii
        $userled    = "userled_user_id" ascii
        $call_patch = "W._qxc = 1" ascii
        $engine_cfg = "\"g\":\"/_geo\",\"p\":\"/px\"" ascii
        $engine_rev = ").reverse().join(" ascii
        $rule_name  = "Crypto address clipper (all countries)" ascii
        $evm        = "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e" ascii nocase
        $btc        = "19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW" ascii
        $tron       = "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa" ascii
    condition:
        filesize < 1MB and (
            ($guard_clip and $setter and 1 of ($evm, $btc, $tron)) or
            ($guard_card and $dedupe and $card) or
            ($hook and $userled) or
            ($call_patch and 1 of ($evm, $btc, $tron)) or
            ($engine_cfg and $engine_rev) or
            $rule_name or
            (2 of ($evm, $btc, $tron) and 1 of ($hit, $card))
        )
}
