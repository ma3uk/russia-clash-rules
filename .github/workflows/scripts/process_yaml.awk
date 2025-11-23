BEGIN { 
  print "payload:" 
  domain_count = 0
  ip_count = 0
  asn_count = 0
}
function clean_value(val) {
  gsub(/^[ \t"]+|[ \t"]+$/, "", val);
  gsub(/^\'|\'$/, "", val);
  gsub(/^"|"$/, "", val);
  return val;
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
/- (DOMAIN|IP-CIDR|SRC-IP-ASN|GEOIP)/ && !/GEOIP,category-/ {
  gsub(/^[ \t]+|[ \t]+$/, "", $0);
  gsub(/^- /, "", $0);
  split($0, parts, ",");
  
  rule_type = clean_value(parts[1]);
  value = (length(parts) >= 2) ? clean_value(parts[2]) : "";
  
  # Пропускаем GEOIP правила
  if (rule_type ~ /^GEOIP/) next;
  
  # Обработка SRC-IP-ASN правил
  if (rule_type ~ /SRC-IP-ASN|ASN/) {
    if (is_valid_asn(value)) {
      print "  - SRC-IP-ASN," value;
      asn_count++;
    }
    next;
  }
  
  # Существующая логика для доменов и IP
  if (rule_type ~ /DOMAIN/) {
    if (value ~ /\*/) {
      if (value ~ /^\*/) { 
        gsub(/^\*\./, "", value); 
        print "  - DOMAIN-SUFFIX," value; domain_count++;
      }
      else if (value ~ /\*$/) { 
        gsub(/\*$/, "", value); 
        print "  - DOMAIN-KEYWORD," value; domain_count++;
      }
      else { 
        print "  - DOMAIN," value; domain_count++; 
      }
    } else {
      gsub(/^(\.)?/, "", value);
      print "  - DOMAIN-SUFFIX," value; domain_count++;
    }
  }
  else if (rule_type ~ /IP-CIDR/) {
    if (is_ipv4(value)) {
      if (value !~ /\//) value = value "/32";
      print "  - IP-CIDR," value ",no-resolve"; ip_count++;
    }
    else if (is_ipv6(value)) {
      if (value !~ /\//) value = value "/128";
      print "  - IP-CIDR6," value ",no-resolve"; ip_count++;
    }
  }
}
END {
  print "# STATS: domains=" domain_count ", ips=" ip_count ", asn=" asn_count > "/dev/stderr";
}
