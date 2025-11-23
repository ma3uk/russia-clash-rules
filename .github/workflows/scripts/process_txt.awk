BEGIN { 
  print "payload:" 
  domain_count = 0
  ip_count = 0
  regex_count = 0
  asn_count = 0
}
function is_valid_asn(asn) {
  if (asn ~ /^[0-9]+$/) {
    num = asn + 0;
    return (num >= 1 && num <= 4294967295);
  }
  return 0;
}
function is_ipv4(addr) {
  if (addr ~ /^([0-9]{1,3}\\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$/) {
    split(addr, parts, "/"); if (parts[2] == "") parts[2] = 32;
    if (parts[2] < 0 || parts[2] > 32) return 0;
    split(parts[1], octets, "."); if (length(octets) != 4) return 0;
    for (i=1; i<=4; i++) if (octets[i] < 0 || octets[i] > 255) return 0;
    return 1;
  }
  return 0;
}
function is_ipv6(addr) {
  if (addr ~ /^([0-9a-fA-F:]+)(\/[0-9]{1,3})?$/) {
    split(addr, parts, "/"); if (parts[2] == "") parts[2] = 128;
    if (parts[2] < 0 || parts[2] > 128) return 0;
    return 1;
  }
  return 0;
}
{
  gsub(/^[ \t]+|[ \t]+$/, "", $0);
  if ($0 ~ /^geosite:/) next;
  
  # Обработка ASN правил
  if ($0 ~ /^(src-ip-asn:|src-asn:|asn:)/) {
    asn = substr($0, index($0, ":") + 1);
    gsub(/^[ \t]+|[ \t]+$/, "", asn);
    if (is_valid_asn(asn)) {
      print "  - SRC-IP-ASN," asn;
      asn_count++;
    }
    next;
  }
  
  # Существующая логика для доменов и IP
  if ($0 ~ /^domain:/) {
    domain = substr($0, 8); gsub(/^[ \t]+|[ \t]+$/, "", domain);
    if (domain ~ /\*/) {
      if (domain ~ /^\*/) { gsub(/^\*\./, "", domain); print "  - DOMAIN-SUFFIX," domain; domain_count++ }
      else if (domain ~ /\*$/) { gsub(/\*$/, "", domain); print "  - DOMAIN-KEYWORD," domain; domain_count++ }
      else { print "  - DOMAIN," domain; domain_count++ }
    } else { print "  - DOMAIN-SUFFIX," domain; domain_count++ }
  }
  else if ($0 ~ /^full:/) {
    domain = substr($0, 6); gsub(/^[ \t]+|[ \t]+$/, "", domain);
    print "  - DOMAIN," domain; domain_count++;
  }
  else if ($0 ~ /^regexp:/) {
    regex = substr($0, 9); gsub(/^[ \t]+|[ \t]+$/, "", regex);
    gsub(/\\/, "\\\\", regex);
    print "  - DOMAIN-REGEX," regex; regex_count++;
  }
  else if ($0 ~ /^ipcidr:/) {
    ip_range = substr($0, 9); gsub(/^[ \t]+|[ \t]+$/, "", ip_range);
    if (is_ipv4(ip_range)) {
      if (ip_range !~ /\//) ip_range = ip_range "/32";
      print "  - IP-CIDR," ip_range ",no-resolve"; ip_count++;
    }
    else if (is_ipv6(ip_range)) {
      if (ip_range !~ /\//) ip_range = ip_range "/128";
      print "  - IP-CIDR6," ip_range ",no-resolve"; ip_count++;
    }
  }
  else {
    if (is_ipv4($0)) {
      ip = $0; if (ip !~ /\//) ip = ip "/32";
      print "  - IP-CIDR," ip ",no-resolve"; ip_count++;
    }
    else if (is_ipv6($0)) {
      ip = $0; if (ip !~ /\//) ip = ip "/128";
      print "  - IP-CIDR6," ip ",no-resolve"; ip_count++;
    }
    else if ($0 ~ /\*/) {
      if ($0 ~ /^\*/) { gsub(/^\*\./, "", $0); print "  - DOMAIN-SUFFIX," $0; domain_count++ }
      else if ($0 ~ /\*$/) { gsub(/\*$/, "", $0); print "  - DOMAIN-KEYWORD," $0; domain_count++ }
      else { print "  - DOMAIN," $0; domain_count++ }
    }
    else {
      # Проверка на ASN без префикса (только числа)
      if (is_valid_asn($0)) {
        print "  - SRC-IP-ASN," $0; asn_count++;
      } else {
        print "  - DOMAIN-SUFFIX," $0; domain_count++;
      }
    }
  }
}
END {
  print "# STATS: domains=" domain_count ", ips=" ip_count ", regex=" regex_count ", asn=" asn_count > "/dev/stderr";
}
