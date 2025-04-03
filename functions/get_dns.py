import dns.resolver

dkim_selector = "default"

def resolve_dns_record(record_type, query):
    try:
        records = [dns_record.to_text() for dns_record in dns.resolver.resolve(query, record_type).rrset]
        return records
    except Exception as e:
        return [f"Error: {str(e)}"]  

def split_ip(ip):
    return list(map(int, ip.split(".")))

def check_dns(domain):
     # A Record
    A_record = resolve_dns_record("A", domain)
    num_ips = len(A_record) if A_record not in (["null"], []) else 0


    # Splitting IP address to octets for dataset
    split_ip_address = None
    if A_record not in (["null"], []):
        first_ip = A_record[0]
        split_ip_address = split_ip(first_ip)
        
        if len(split_ip_address) == 4:
            first_octet = split_ip_address[0]
            second_octet = split_ip_address[1]
            third_octet = split_ip_address[2]
            fourth_octet = split_ip_address[3]

    # TXT Records 
    txt_records = resolve_dns_record("TXT", domain)
    txt_status = 1 if txt_records not in ([], ["0"]) else 0  

    # SPF Record 
    spf_record = [record for record in txt_records if "v=spf1" in record]
    spf_status = 1 if spf_record else 0  

    # MX 
    mx_records = resolve_dns_record("MX", domain)
    mx_status = 1 if mx_records not in ([], ["0"]) else 0  

    # DKIM 
    dkim_records = resolve_dns_record("TXT", f"{dkim_selector}._domainkey.{domain}")
    dkim_status = 1 if dkim_records not in ([], ["0"]) else 0  

    # DMARC
    dmarc_records = resolve_dns_record("TXT", f"_dmarc.{domain}")
    dmarc_status = 1 if dmarc_records not in ([], ["0"]) else 0  

    return A_record, num_ips, first_octet, second_octet, third_octet, fourth_octet, txt_status, spf_status, mx_status, dkim_status, dmarc_status