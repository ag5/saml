package saml

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	"io"
	"net/http"
)

type ResponseWithIssuer struct {
	Issuer *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
}

func EntityIDFromRequest(r *http.Request) (string, error) {
	queryParameterData := r.URL.Query().Get("SAMLResponse")

	rawResponseBuf, err := base64.StdEncoding.DecodeString(queryParameterData)
	if err != nil {
		return "", fmt.Errorf("unable to parse base64: %s", err)

	}

	gr, err := io.ReadAll(newSaferFlateReader(bytes.NewBuffer(rawResponseBuf)))
	if err != nil {
		return "", err
	}

	if err = xrv.Validate(bytes.NewReader(gr)); err != nil {
		return "", err
	}

	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(gr); err != nil {
		return "", err
	}

	var resp ResponseWithIssuer
	if err := unmarshalElement(doc.Root(), &resp); err != nil {
		return "", err
	}

	return resp.Issuer.Value, nil
}
