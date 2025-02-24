import os
import re
import xml.etree.ElementTree as ET
from fuzzywuzzy import fuzz
import jellyfish

# Common stopwords to remove from both input & candidate tokens
STOPWORDS = {"al", "el", "bin", "ibn", "ben"}

def normalize_token(token):
    """
    Lowercase, remove punctuation like apostrophes, commas, etc.
    """
    token = token.lower().strip()
    token = re.sub(r"[’'`,]", "", token)
    return token

def strip_stopwords(tokens):
    """
    Remove tokens like 'al', 'bin', 'ibn', 'ben'.
    """
    return [t for t in tokens if t not in STOPWORDS]

def split_name(name):
    """
    Split name into tokens, removing common noise. E.g. "AL-MADANI, Hashem Ismail Ali Ahmed" => ["madani","hashem","ismail","ali","ahmed"]
    """
    # Replace commas & hyphens with spaces
    name = re.sub(r"[,\-]", " ", name)
    raw_tokens = re.split(r"\s+", name.strip())
    tokens = [normalize_token(t) for t in raw_tokens if t.strip()]
    # Remove stopwords
    tokens = strip_stopwords(tokens)
    return tokens

def partial_coverage_jw(input_name, candidate_name):
    """
    Partial coverage with Jaro–Winkler:
      1) Tokenize both names (remove stopwords).
      2) For each INPUT token, find the maximum JW similarity among CANDIDATE tokens. 
      3) Average these maxima => coverage in [0..1].
      4) If coverage >= 0.95, clamp to 1.0 => 100%. 
      5) Return coverage * 100.

    This mimics how OFAC often returns 100% if all input tokens 
    have a near-perfect match in the candidate's tokens, ignoring leftover tokens.
    """
    input_tokens = split_name(input_name)
    candidate_tokens = split_name(candidate_name)
    if not input_tokens or not candidate_tokens:
        return 0.0
    
    total_sim = 0.0
    for itok in input_tokens:
        best_sim = 0.0
        for ctok in candidate_tokens:
            jw = jellyfish.jaro_winkler_similarity(itok, ctok)
            if jw > best_sim:
                best_sim = jw
        total_sim += best_sim
    
    coverage = total_sim / len(input_tokens)
    
    # If coverage >= 0.95, clamp to 100%. 
    if coverage >= 0.95:
        coverage = 1.0
    
    return coverage * 100.0

def parse_sdn_list(xml_file):
    """
    Parse OFAC's SDN XML, returning a list of dicts like:
      {
        "full_name": "Isma'il Fu'ad Rasul AHMED",
        "sdn_type": "individual",
        "address": ...,
        ...
      }
    Including <aka> items as separate rows.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    if root.tag.startswith("{"):
        ns_uri = root.tag.split("}")[0].strip("{")
        ns = {"ns": ns_uri}
        entry_path = ".//ns:sdnEntry"
    else:
        ns = None
        entry_path = ".//sdnEntry"

    def ns_find(elem, path):
        return elem.find(path, ns) if ns else elem.find(path)
    
    def ns_findall(elem, path):
        return elem.findall(path, ns) if ns else elem.findall(path)

    sdn_entries = []
    entries = root.findall(entry_path, ns) if ns else root.findall(entry_path)

    for e in entries:
        fn_el = ns_find(e, "ns:firstName") if ns else ns_find(e, "firstName")
        ln_el = ns_find(e, "ns:lastName") if ns else ns_find(e, "lastName")
        sdn_type_el = ns_find(e, "ns:sdnType") if ns else ns_find(e, "sdnType")

        addr_el = ns_find(e, "./ns:addressList/ns:address/ns:address1") if ns else ns_find(e, "./addressList/address/address1")
        city_el = ns_find(e, "./ns:addressList/ns:address/ns:city") if ns else ns_find(e, "./addressList/address/city")
        country_el = ns_find(e, "./ns:addressList/ns:address/ns:country") if ns else ns_find(e, "./addressList/address/country")
        nat_el = ns_find(e, "./ns:nationalityList/ns:nationality") if ns else ns_find(e, "./nationalityList/nationality")

        first_name = fn_el.text.strip() if (fn_el is not None and fn_el.text) else ""
        last_name = ln_el.text.strip() if (ln_el is not None and ln_el.text) else ""
        sdn_type = sdn_type_el.text.strip().lower() if (sdn_type_el is not None and sdn_type_el.text) else "unknown"

        address = addr_el.text.strip() if (addr_el is not None and addr_el.text) else ""
        city = city_el.text.strip() if (city_el is not None and city_el.text) else ""
        country = country_el.text.strip() if (country_el is not None and country_el.text) else ""
        nationality = nat_el.text.strip() if (nat_el is not None and nat_el.text) else ""

        # Birth place(s)
        bp_list = ns_findall(e, "./ns:placeOfBirthList/ns:placeOfBirthItem/ns:placeOfBirth") if ns else \
                  ns_findall(e, "./placeOfBirthList/placeOfBirthItem/placeOfBirth")
        if not bp_list:
            bp_list = ns_findall(e, "./ns:placeOfBirthList/ns:placeOfBirth") if ns else \
                      ns_findall(e, "./placeOfBirthList/placeOfBirth")
        birth_place_txt = ", ".join(bp.text.strip() for bp in bp_list if bp.text)

        # Birth date(s)
        bd_list = ns_findall(e, "./ns:dateOfBirthList/ns:dateOfBirthItem/ns:dateOfBirth") if ns else \
                  ns_findall(e, "./dateOfBirthList/dateOfBirthItem/dateOfBirth")
        if not bd_list:
            bd_list = ns_findall(e, "./ns:dateOfBirthList/ns:dateOfBirth") if ns else \
                      ns_findall(e, "./dateOfBirthList/dateOfBirth")
        birth_date_txt = ", ".join(bd.text.strip() for bd in bd_list if bd.text)

        main_full_name = f"{first_name} {last_name}".strip()
        if main_full_name:
            sdn_entries.append({
                "full_name": main_full_name,
                "sdn_type": sdn_type,
                "address": address,
                "city": city,
                "country": country,
                "nationality": nationality,
                "birth_place": birth_place_txt,
                "birth_date": birth_date_txt
            })
        
        # parse <akaList>
        aka_el = ns_find(e, "ns:akaList") if ns else ns_find(e, "akaList")
        if aka_el is not None:
            aka_items = ns_findall(aka_el, "ns:aka") if ns else ns_findall(aka_el, "aka")
            for aka in aka_items:
                afn_el = ns_find(aka, "ns:firstName") if ns else ns_find(aka, "firstName")
                aln_el = ns_find(aka, "ns:lastName") if ns else ns_find(aka, "lastName")
                afn = afn_el.text.strip() if (afn_el is not None and afn_el.text) else ""
                aln = aln_el.text.strip() if (aln_el is not None and aln_el.text) else ""
                aka_full = f"{afn} {aln}".strip()
                if aka_full:
                    sdn_entries.append({
                        "full_name": aka_full,
                        "sdn_type": sdn_type,
                        "address": address,
                        "city": city,
                        "country": country,
                        "nationality": nationality,
                        "birth_place": birth_place_txt,
                        "birth_date": birth_date_txt
                    })
    return sdn_entries

def assess_sdn_match(input_data, sdn_entries):
    """
    Steps:
      1) Relaxed type check (substring). If user typed 'individual', skip if not found in candidate's sdn_type.
      2) If user provided any additional fields (address, city, etc.), require >=1 partial-ratio match (>=80).
      3) Among survivors, pick the highest partial coverage Jaro–Winkler score.
    """
    user_full_name = input_data["full_name"].strip()
    user_sdn_type = input_data["sdn_type"].strip().lower()

    # Additional fields
    extras = ["address", "city", "country", "nationality", "birth_place", "birth_date"]
    provided_extras = {f: input_data[f].strip() for f in extras if input_data[f].strip()}

    best_match = None
    best_score = 0.0

    for entry in sdn_entries:
        candidate_name = entry["full_name"]
        candidate_type = entry["sdn_type"].strip().lower()

        # Step 1: Relaxed type check
        if user_sdn_type and (user_sdn_type not in candidate_type):
            continue

        # Step 2: Additional fields => require >=1 partial match if user provided them
        addl_match_count = 0
        for field, val_in in provided_extras.items():
            cand_val = entry.get(field, "").lower()
            if cand_val:
                ratio = fuzz.partial_ratio(val_in.lower(), cand_val)
                if ratio >= 80:
                    addl_match_count += 1
        if provided_extras and addl_match_count < 1:
            continue

        # Step 3: partial coverage with Jaro–Winkler
        score = partial_coverage_jw(user_full_name, candidate_name)
        if score > best_score:
            best_score = score
            best_match = entry

    if not best_match:
        return "No valid match found."
    
    explanation = (
        f"Match found: {best_match['full_name']} (Score: {best_score:.2f}%).\n"
        "Using partial-coverage Jaro–Winkler:\n"
        " - We remove stopwords ('al','bin','ibn','ben').\n"
        " - For each input token, find its best JW match among candidate tokens.\n"
        " - Average => coverage, clamp >=0.95 to 100.\n"
        " - Leftover candidate tokens do not penalize the match.\n\n"
        f"Matched Entry Details:\n"
        f"Name: {best_match['full_name']}\n"
        f"Type: {best_match['sdn_type']}\n"
        f"Address: {best_match['address']}, {best_match['city']}, {best_match['country']}\n"
        f"Nationality: {best_match['nationality']}\n"
        f"Birth Place: {best_match['birth_place']}\n"
        f"Birth Date: {best_match['birth_date']}\n"
    )
    return explanation

def get_top_matches(input_data, sdn_entries, limit=20):
    """
    Return the top N (default 20) by partial_coverage_jw (>1.0).
    """
    user_full_name = input_data["full_name"].strip()
    results = []
    for entry in sdn_entries:
        score = partial_coverage_jw(user_full_name, entry["full_name"])
        if score > 1.0:  # filter out near-0 results
            results.append((entry, score))
    results.sort(key=lambda x: x[1], reverse=True)
    return results[:limit]

if __name__ == '__main__':
    input_data = {
        "full_name": input("Enter full name: "),
        "sdn_type": input("Enter type (individual, vessel, organization, company) (leave blank if unknown): "),
        "address": input("Enter address (leave blank if unknown): "),
        "city": input("Enter city (leave blank if unknown): "),
        "country": input("Enter country (leave blank if unknown): "),
        "nationality": input("Enter nationality (leave blank if unknown): "),
        "birth_place": input("Enter place of birth (leave blank if unknown): "),
        "birth_date": input("Enter date of birth (YYYY-MM-DD, leave blank if unknown): ")
    }

    xml_path = "/Users/mustafaahmed/Downloads/SDN.XML"  # Adjust path
    sdn_data = parse_sdn_list(xml_path)

    # 1) Show the best single match
    best_result = assess_sdn_match(input_data, sdn_data)
    print("\n" + best_result)

    # 2) Show the top 20 partial coverage matches
    print("\nTop 20 partial-coverage matches:")
    top_list = get_top_matches(input_data, sdn_data, limit=20)
    for i, (entry, score) in enumerate(top_list, start=1):
        print(f"{i}. {entry['full_name']} (Score: {score:.2f}%) - Type: {entry['sdn_type']}")
