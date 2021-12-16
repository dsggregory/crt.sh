package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	_ "github.com/lib/pq"
)

const (
	NtDNSName    = "san:dNSName"
	NtCommonName = "2.5.4.3" // oid
)

const (
	ColnmID             = "id"
	ColnmIssuer         = "issuer_name"
	ColnmNotAfter       = "not_after"
	ColnmNotBefore      = "not_before"
	ColnmSerial         = "serial_number"
	ColnmEntryTimestamp = "entry_timestamp"
	ColnmSubject        = "subject_name"
	ColnmFormatted      = "formatted"
)

var QueryDomain string = `
WITH ci AS (
    SELECT min(sub.CERTIFICATE_ID) ID,
           min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
           array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
           x509_commonName(sub.CERTIFICATE) COMMON_NAME,
           x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
           x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
           encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER,
           x509_subjectName(sub.CERTIFICATE) SUBJECT_NAME,
           x509_print(sub.CERTIFICATE, NULL, 196608) FORMATTED
        FROM (SELECT *
                  FROM certificate_and_identities cai
                  WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
                      AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')
                      AND cai.NAME_TYPE = $2
                  LIMIT 10000
             ) sub
        GROUP BY sub.CERTIFICATE
)
SELECT ci.ISSUER_CA_ID,
        ca.NAME ISSUER_NAME,
        ci.COMMON_NAME,
        array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE,
        ci.ID ID,
        le.ENTRY_TIMESTAMP,
        ci.NOT_BEFORE,
        ci.NOT_AFTER,
        ci.SERIAL_NUMBER,
        ci.SUBJECT_NAME,
        ci.FORMATTED
    FROM ci
            LEFT JOIN LATERAL (
                SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
                    FROM ct_log_entry ctle
                    WHERE ctle.CERTIFICATE_ID = ci.ID
            ) le ON TRUE,
         ca
    WHERE ci.ISSUER_CA_ID = ca.ID
    ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;
`

const qCertBase = `
SELECT id as ID,
       x509_print(certificate, NULL, 196608) as FORMATTED,
       x509_subjectName(CERTIFICATE) as SUBJECT_NAME,
       encode(x509_serialNumber(CERTIFICATE), 'hex') as SERIAL_NUMBER,
       x509_notAfter(CERTIFICATE) as NOT_AFTER,
       x509_notBefore(CERTIFICATE) as NOT_BEFORE,
       cast(issuer_ca_id as varchar) as ISSUER_NAME
	FROM certificate 
`

var QuerySha1Fingerprint string = qCertBase + `WHERE digest(certificate, $1) = $2;`

var QuerySKID string = qCertBase + `WHERE x509_subjectKeyIdentifier(certificate, 'hex') = $1;`

func getRows(rows *sql.Rows) ([]map[string]interface{}, error) {
	// [issuer_ca_id issuer_name common_name name_value id entry_timestamp not_before not_after serial_number raw]
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	numColumns := len(columns)

	values := make([]interface{}, numColumns)
	for i := range values {
		values[i] = new(interface{})
	}

	var results []map[string]interface{}
	for rows.Next() {
		if err = rows.Scan(values...); err != nil {
			return nil, err
		}
		dest := make(map[string]interface{}, numColumns)
		for i, column := range columns {
			dest[column] = *(values[i].(*interface{}))
		}
		results = append(results, dest)
	}

	return results, nil
}

func main() {
	var oOutType string
	var oArgType string
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [opts] <query>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&oArgType, "t", "", "type of the query param - [domain, fingerprint, SKID]. Required for SKID query and optional for others")
	flag.StringVar(&oOutType, "o", "list", "specifies the output format - [list, text, JSON]")
	flag.Parse()
	oArgType = strings.ToLower(oArgType)
	oOutType = strings.ToLower(oOutType)

	pi := fmt.Sprintf("host=crt.sh port=5432 user=guest dbname=certwatch sslmode=disable binary_parameters=yes")
	db, err := sql.Open("postgres", pi)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer db.Close()

	var isHexRe = regexp.MustCompile(`^[a-fA-F0-9]+$`)

	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}
	qArg := flag.Args()[0]
	var rows *sql.Rows
	switch {
	case oArgType == "domain" || strings.Contains(qArg, "."):
		qArg = fmt.Sprintf("%%.%s", qArg)
		rows, err = db.Query(QueryDomain, qArg, NtDNSName)
	case oArgType == "skid":
		rows, err = db.Query(QuerySKID, fmt.Sprintf(`\x%s`, qArg))
	case oArgType == "fingerprint" || isHexRe.MatchString(qArg) && len(qArg) == 40: // sha1 fingerprint
		rows, err = db.Query(QuerySha1Fingerprint, "sha1", fmt.Sprintf(`\x%s`, qArg))
	case oArgType == "fingerprint" || isHexRe.MatchString(qArg) && len(qArg) == 64: // sha256 fingerprint
		rows, err = db.Query(QuerySha1Fingerprint, "sha256", fmt.Sprintf(`\x%s`, qArg))
	default:
		err = fmt.Errorf("unknown query type for input")
	}
	if err != nil {
		log.Fatal(err.Error())
	}
	if rows == nil {
		log.Fatal("no results:", err)
	}

	results, err := getRows(rows)
	if err != nil {
		log.Fatal(err.Error())
	}

	if oOutType == "json" {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			log.Fatal("json", err.Error())
		}
		fmt.Println(string(data))
	} else {
		for _, res := range results {
			if oOutType == "text" {
				fmt.Println(res[ColnmFormatted])
			} else {
				fmt.Printf(`Certificate ID: %d`, res[ColnmID])
				if res[ColnmEntryTimestamp] != nil {
					fmt.Printf(`  Entered: %s`, res[ColnmEntryTimestamp])
				}
				fmt.Printf(`
  Subject: %s
  Serial: %s
  Issuer: %s
  NotBefore: %s
  NotAfter: %s
`,
					res[ColnmSubject], res[ColnmSerial], res[ColnmIssuer], res[ColnmNotBefore], res[ColnmNotAfter])
			}
		}
	}
}
