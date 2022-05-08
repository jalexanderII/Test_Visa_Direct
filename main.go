package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/jalexanderII/Test_Visa_Direct/models"
	"github.com/jalexanderII/Test_Visa_Direct/utils"
	"gopkg.in/square/go-jose.v2"
)

var (
	baseUrl             = utils.GetEnv("SANDBOXURL")
	pullFundEndPoint    = utils.GetEnv("PULLFUNDSURL")
	pushFundEndPoint    = utils.GetEnv("PUSHFUNDSURL")
	transactionEndPoint = utils.GetEnv("TRXNQUERYURL")

	username = utils.GetEnv("USERNAME")
	password = utils.GetEnv("PASSWORD")

	// Two Way SSL Credentials
	clientCertificateFile    = utils.GetEnv("SSLCERTPATH")
	clientCertificateKeyFile = utils.GetEnv("SSLCERTKEYPATH")
	caCertificateFile        = utils.GetEnv("CACERTPATH")

	// MLE KEYS
	mleClientPrivateKeyPath        = utils.GetEnv("MLEPRIVATEKEYPATH")
	mleServerPublicCertificatePath = utils.GetEnv("MLEPUBLICKEYPATH")
	keyId                          = utils.GetEnv("MLEKEYID")
)

func main() {
	acquiringBin := "408999"

	t := time.Now()
	localTransactionDateTime := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())

	log.Println("####################################################################################")
	log.Println("######################## START PULL (OCT)  Transaction #############################")
	log.Println("####################################################################################")

	pullFundsTransactionRequest := models.PullFundsTransactionRequest{
		Surcharge:                                "11.99",
		CpsAuthorizationCharacteristicsIndicator: "Y",
		RiskAssessmentData: models.RiskAssessmentData{
			TraExemptionIndicator:             true,
			TrustedMerchantExemptionIndicator: true,
			ScpExemptionIndicator:             true,
			DelegatedAuthenticationIndicator:  true,
			LowValueExemptionIndicator:        true,
		},
		AccountType:        "20",
		SenderCurrencyCode: "USD",
		AddressVerificationData: models.AddressVerificationData{
			Street:     "XYZ St",
			PostalCode: "12345",
		},
		Cavv:                          "0000010926000071934977253000000000000000",
		SenderPrimaryAccountNumber:    "4957030005123304",
		VisaMerchantIdentifier:        "73625198",
		ForeignExchangeFeeTransaction: "11.99",
		SenderCardExpiryDate:          "2020-03",
		NationalReimbursementFee:      "11.22",
		Amount:                        "100",
		LocalTransactionDateTime:      localTransactionDateTime,
		ColombiaNationalServiceData: models.ColombiaNationalServiceData{
			AddValueTaxReturn:                     "10.00",
			TaxAmountConsumption:                  "10.00",
			NationalNetReimbursementFeeBaseAmount: "20.00",
			AddValueTaxAmount:                     "10.00",
			NationalNetMiscAmount:                 "10.00",
			CountryCodeNationalService:            "170",
			NationalChargebackReason:              "11",
			EmvTransactionIndicator:               "1",
			NationalNetMiscAmountType:             "A",
			CostTransactionIndicator:              "0",
			NationalReimbursementFee:              "20.00",
		},
		PointOfServiceData: models.PointOfServiceData{
			PanEntryMode:     "10",
			PosConditionCode: "52",
			MotoECIIndicator: "5",
		},
		CardAcceptor: models.CardAcceptor{
			Address: models.Address{
				Country: "USA",
				ZipCode: "94404",
				County:  "SanMateo",
				State:   "CA",
			},
			IdCode:     "CA-IDCode-77765",
			Name:       "Acceptor 1",
			TerminalId: "TID-9999",
		},
		AcquirerCountryCode:        "840",
		AcquiringBin:               acquiringBin,
		RetrievalReferenceNumber:   "412770451018",
		SystemsTraceAuditNumber:    "451018",
		BusinessApplicationId:      "AA",
		SettlementServiceIndicator: "9",
	}
	aftPayload, err := json.Marshal(pullFundsTransactionRequest)
	if err != nil {
		log.Println("[Error] marshalling pullFundsTransactionRequest: ")
		fmt.Println(err)
	}
	encAFTData := map[string]string{"encData": createJWE(string(aftPayload), keyId, mleServerPublicCertificatePath)}
	encryptedAFTPayload, err := json.Marshal(encAFTData)
	if err != nil {
		log.Println("[Error] marshalling enc data: ")
		log.Println(err)
	}

	responsePayloadAFT := invokeAPI(pullFundEndPoint, http.MethodPost, string(encryptedAFTPayload))
	var pullFundsTransactionResponse models.PullFundsTransactionResponse
	err = json.Unmarshal([]byte(responsePayloadAFT), &pullFundsTransactionResponse)
	if err != nil {
		log.Println("[Error] unmarshalling pullFundsTransactionResponse: ")
		log.Println(err)
	}

	log.Printf("AFT Response Data: %+v", pullFundsTransactionResponse)

	log.Println("####################################################################################")
	log.Println("######################## END PULL (OCT)  Transaction ###############################")
	log.Println("####################################################################################")

	log.Println("####################################################################################")
	log.Println("######################## START PUSH (OCT)  Transaction #############################")
	log.Println("####################################################################################")

	pushFundsTransactionRequest := models.PushFundsTransactionRequest{
		Amount:                   "124.05",
		SenderAddress:            "901MetroCenterBlvd",
		LocalTransactionDateTime: localTransactionDateTime,
		PointOfServiceData: models.PointOfServiceData{
			PanEntryMode:     "90",
			PosConditionCode: "00",
			MotoECIIndicator: "0",
		},
		RecipientPrimaryAccountNumber: "4957030420210496",
		ColombiaNationalServiceData: models.ColombiaNationalServiceData{
			AddValueTaxReturn:                     "10.00",
			TaxAmountConsumption:                  "10.00",
			NationalNetReimbursementFeeBaseAmount: "20.00",
			AddValueTaxAmount:                     "10.00",
			NationalNetMiscAmount:                 "10.00",
			CountryCodeNationalService:            "170",
			NationalChargebackReason:              "11",
			EmvTransactionIndicator:               "1",
			NationalNetMiscAmountType:             "A",
			CostTransactionIndicator:              "0",
			NationalReimbursementFee:              "20.00",
		},
		CardAcceptor: models.CardAcceptor{
			Address: models.Address{
				Country: "USA",
				ZipCode: "94404",
				County:  "SanMateo",
				State:   "CA",
			},
			IdCode:     "CA-IDCode-77765",
			Name:       "VisaInc.USA-FosterCity",
			TerminalId: "TID-9999",
		},
		SenderReference:            "",
		AcquirerCountryCode:        "840",
		AcquiringBin:               acquiringBin,
		RetrievalReferenceNumber:   "412770451018",
		SenderCity:                 "FosterCity",
		SenderStateCode:            "CA",
		SystemsTraceAuditNumber:    "451018",
		SenderName:                 "MohammedQasim",
		BusinessApplicationId:      "AA",
		SettlementServiceIndicator: "9",
		MerchantCategoryCode:       "6012",
		TransactionCurrencyCode:    "USD",
		RecipientName:              "rohan",
		SenderCountryCode:          "124",
		SourceOfFundsCode:          "05",
		SenderAccountNumber:        "4653459515756154",
	}
	octPayload, err := json.Marshal(pushFundsTransactionRequest)
	if err != nil {
		log.Println("[Error] marshalling pushFundsTransactionRequest: ")
		fmt.Println(err)
	}
	encData := map[string]string{"encData": createJWE(string(octPayload), keyId, mleServerPublicCertificatePath)}
	encryptedPayload, err := json.Marshal(encData)
	if err != nil {
		log.Println("[Error] marshalling enc data: ")
		log.Println(err)
	}

	responsePayload := invokeAPI(pushFundEndPoint, http.MethodPost, string(encryptedPayload))
	var pushFundsTransactionResponse models.PushFundsTransactionResponse
	err = json.Unmarshal([]byte(responsePayload), &pushFundsTransactionResponse)
	if err != nil {
		log.Println("[Error] unmarshalling pushFundsTransactionResponse: ")
		log.Println(err)
	}
	log.Printf("OCT Response Data: %+v", pushFundsTransactionResponse)

	log.Println("####################################################################################")
	log.Println("######################## END PUSH (OCT)  Transaction ###############################")
	log.Println("####################################################################################")

	log.Println("####################################################################################")
	log.Println("######################## START QUERY API ###########################################")
	log.Println("####################################################################################")

	var responseMap map[string]json.RawMessage
	err = json.Unmarshal([]byte(responsePayload), &responseMap)
	if err != nil {
		log.Println("[Error] unmarshalling responsePayload for query: ")
		log.Println(err)
	}

	queryString := "?acquiringBIN=" + acquiringBin + "&transactionIdentifier=" + string(responseMap["transactionIdentifier"])
	transactionQueryEndPoint := transactionEndPoint + queryString

	responsePayload = invokeAPI(transactionQueryEndPoint, http.MethodGet, "")
	log.Println("Query Response Data: ", responsePayload)

	log.Println("####################################################################################")
	log.Println("######################## END QUERY API #############################################")
	log.Println("####################################################################################")

}

func invokeAPI(resourcePath string, httpMethod string, payload string) string {
	// Load CA Cert
	clientCACert, err := ioutil.ReadFile(caCertificateFile)
	if err != nil {
		log.Println("[Error] Loading clientCACert: ")
		panic(err)
	}

	// Load Client Key Pair
	clientKeyPair, err := tls.LoadX509KeyPair(clientCertificateFile, clientCertificateKeyFile)
	if err != nil {
		log.Println("[Error] Loading clientKeyPair: ")
		fmt.Println(err)
	}

	clientCertPool, _ := x509.SystemCertPool()
	if clientCertPool == nil {
		clientCertPool = x509.NewCertPool()
	}

	clientCertPool.AppendCertsFromPEM(clientCACert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientKeyPair},
		RootCAs:      clientCertPool,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: transport}

	apiUrl := baseUrl + resourcePath
	var request *http.Request = nil
	if payload != "" {
		// log.Println("Request Payload: ", payload)
		request, err = http.NewRequest(httpMethod, apiUrl, bytes.NewBuffer([]byte(payload)))
	} else {
		request, err = http.NewRequest(httpMethod, apiUrl, nil)
	}

	if err != nil {
		log.Println("[Error] Making NewRequest: ", apiUrl)
		panic(err)
	}
	request.SetBasicAuth(username, password)
	request.Header.Set("keyId", keyId)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")

	// log.Println("Invoking API:", httpMethod, resourcePath)
	resp, err := client.Do(request)
	if err != nil {
		log.Println("[Error] Invoking API: ", resourcePath)
		panic(err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("[Error] ioutil.ReadAll: ")
		panic(err)
	}
	log.Println("Http Status :", resp.Status)
	// log.Println("Response Headers:", resp.Header)

	encryptedResponsePayload := string(body)
	// log.Println("Response Payload: ", encryptedResponsePayload)

	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		decryptedData := decryptJWE(encryptedResponsePayload, mleClientPrivateKeyPath)
		panic(errors.New("error when invoking visa api. " + decryptedData))
	}

	// log.Println("Response Body:", encryptedResponsePayload)
	decryptedData := decryptJWE(encryptedResponsePayload, mleClientPrivateKeyPath)
	return decryptedData
}

func createJWE(payload string, keyId string, mleServerPublicCertificatePath string) string {
	// Instantiate an encrypter using RSA-OAEP-256 with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.
	publicKey := loadPublicKey(mleServerPublicCertificatePath)
	opts := new(jose.EncrypterOptions)

	iat := currentMillis()

	opts.WithHeader("kid", keyId)
	opts.WithHeader("iat", iat)
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: publicKey}, opts)
	if err != nil {
		log.Println("[Error] NewEncrypter: ")
		panic(err)
	}

	// Encrypt a sample plaintext. Calling the encrypter returns an encrypted
	// JWE object, which can then be serialized for output afterwards. An error
	// would indicate a problem in an underlying cryptographic primitive.
	object, err := encrypter.Encrypt([]byte(payload))
	if err != nil {
		log.Println("[Error] Encrypt: ")
		panic(err)
	}

	// Serialize the encrypted object using the compact serialization format.
	serialized, err := object.CompactSerialize()
	if err != nil {
		log.Println("[Error] CompactSerialize: ")
		panic(err)
	}
	return serialized
}

func currentMillis() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func loadPublicKey(certFilePath string) *rsa.PublicKey {
	certificate, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		log.Println("[Error] loadPublicKey certificate: ")
		panic(err)
	}
	block, _ := pem.Decode(certificate)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	return cert.PublicKey.(*rsa.PublicKey)
}

func parseEncryptedResponse(encryptedPayload string) EncryptedResponse {
	var encryptedResponse EncryptedResponse
	err := json.Unmarshal([]byte(encryptedPayload), &encryptedResponse)

	if err != nil {
		log.Println("[Error] parseEncryptedResponse: ")
		panic(err)
	}
	return encryptedResponse
}

func decryptJWE(encryptedPayload string, mleClientPrivateKeyPath string) string {

	encryptedData := parseEncryptedResponse(encryptedPayload)

	// Parse the serialized, encrypted JWE object. An error would indicate that
	// the given input did not represent a valid message.
	object, err := jose.ParseEncrypted(encryptedData.EncData)
	if err != nil {
		log.Println("[Error] decryptJWE ParseEncrypted: ")
		panic(err)
	}

	// Now we can decrypt and get back our original plaintext. An error here
	// would indicate the message failed to decrypt, e.g. because the auth
	// tag was broken or the message was tampered with.
	privateKey := loadPrivateKey(mleClientPrivateKeyPath)
	decrypted, err := object.Decrypt(privateKey)
	if err != nil {
		log.Println("[Error] Decrypt privateKey: ")
		panic(err)
	}

	return string(decrypted)
}

// Load Private Key from file
func loadPrivateKey(keyFilePath string) *rsa.PrivateKey {
	keyPem, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		log.Println("[Error] loadPrivateKey ReadFile: ")
		panic(err)
	}

	block, _ := pem.Decode(keyPem)
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Println("[Error] ParsePKCS1PrivateKey: ")
		panic(err)
	}
	return priv
}

type EncryptedResponse struct {
	EncData string
}
