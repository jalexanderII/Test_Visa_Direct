package models

type RiskAssessmentData struct {
	TraExemptionIndicator             bool `json:"traExemptionIndicator"`
	TrustedMerchantExemptionIndicator bool `json:"trustedMerchantExemptionIndicator"`
	ScpExemptionIndicator             bool `json:"scpExemptionIndicator"`
	DelegatedAuthenticationIndicator  bool `json:"delegatedAuthenticationIndicator"`
	LowValueExemptionIndicator        bool `json:"lowValueExemptionIndicator"`
}

type ColombiaNationalServiceData struct {
	AddValueTaxReturn                     string `json:"addValueTaxReturn"`
	TaxAmountConsumption                  string `json:"taxAmountConsumption"`
	NationalNetReimbursementFeeBaseAmount string `json:"nationalNetReimbursementFeeBaseAmount"`
	AddValueTaxAmount                     string `json:"addValueTaxAmount"`
	NationalNetMiscAmount                 string `json:"nationalNetMiscAmount"`
	CountryCodeNationalService            string `json:"countryCodeNationalService"`
	NationalChargebackReason              string `json:"nationalChargebackReason"`
	EmvTransactionIndicator               string `json:"emvTransactionIndicator"`
	NationalNetMiscAmountType             string `json:"nationalNetMiscAmountType"`
	CostTransactionIndicator              string `json:"costTransactionIndicator"`
	NationalReimbursementFee              string `json:"nationalReimbursementFee"`
}

type Address struct {
	Country string `json:"country"`
	ZipCode string `json:"zipCode"`
	County  string `json:"county"`
	State   string `json:"state"`
}

type CardAcceptor struct {
	Address    Address `json:"address"`
	IdCode     string  `json:"idCode"`
	Name       string  `json:"name"`
	TerminalId string  `json:"terminalId"`
}

type AddressVerificationData struct {
	Street     string `json:"street"`
	PostalCode string `json:"postalCode"`
}

type PointOfServiceData struct {
	PanEntryMode     string `json:"panEntryMode"`
	PosConditionCode string `json:"posConditionCode"`
	MotoECIIndicator string `json:"motoECIIndicator"`
}

// PullFundsTransactionRequest Resource debits (pulls) funds from a sender's Visa account (in preparation for
// pushing funds to a recipient's account) by initiating a financial message called an Account Funding Transaction (AFT)
type PullFundsTransactionRequest struct {
	Surcharge                                string                      `json:"surcharge"`
	Amount                                   string                      `json:"amount"`
	LocalTransactionDateTime                 string                      `json:"localTransactionDateTime"`
	CpsAuthorizationCharacteristicsIndicator string                      `json:"cpsAuthorizationCharacteristicsIndicator"`
	RiskAssessmentData                       RiskAssessmentData          `json:"riskAssessmentData"`
	ColombiaNationalServiceData              ColombiaNationalServiceData `json:"colombiaNationalServiceData"`
	CardAcceptor                             CardAcceptor                `json:"cardAcceptor"`
	AcquirerCountryCode                      string                      `json:"acquirerCountryCode"`
	AccountType                              string                      `json:"accountType"`
	AcquiringBin                             string                      `json:"acquiringBin"`
	SenderCurrencyCode                       string                      `json:"senderCurrencyCode"`
	RetrievalReferenceNumber                 string                      `json:"retrievalReferenceNumber"`
	AddressVerificationData                  AddressVerificationData     `json:"addressVerificationData"`
	Cavv                                     string                      `json:"cavv"`
	SystemsTraceAuditNumber                  string                      `json:"systemsTraceAuditNumber"`
	BusinessApplicationId                    string                      `json:"businessApplicationId"`
	SenderPrimaryAccountNumber               string                      `json:"senderPrimaryAccountNumber"`
	SettlementServiceIndicator               string                      `json:"settlementServiceIndicator"`
	VisaMerchantIdentifier                   string                      `json:"visaMerchantIdentifier"`
	ForeignExchangeFeeTransaction            string                      `json:"foreignExchangeFeeTransaction"`
	SenderCardExpiryDate                     string                      `json:"senderCardExpiryDate"`
	NationalReimbursementFee                 string                      `json:"nationalReimbursementFee"`
	PointOfServiceData                       PointOfServiceData          `json:"pointOfServiceData"`
}

type DeferredOCTData struct {
	RequestType      string `json:"requestType"`
	DeferredDateTime string `json:"deferredDateTime"` // Format of this value will be in CCYYMMDDHHMM.
}

type SettlementFlags struct {
	SettlementResponsibilityFlag string `json:"settlementResponsibilityFlag"`
	GivPreviouslyUpdatedFlag     string `json:"givPreviouslyUpdatedFlag"`
	GivUpdatedFlag               string `json:"givUpdatedFlag"`
	SettlementServiceFlag        string `json:"settlementServiceFlag"`
}

type VauRTAuthReplacementData struct {
	ReplaceDateExpiration string `json:"replaceDateExpiration"` // Format: YYYY-MM
	ReplacementCardID     string `json:"replacementCardID"`
	VauAccntStatus        string `json:"vauAccntStatus"`
	VauErrorReasonCode    string `json:"vauErrorReasonCode"`
	VauFlag               string `json:"vauFlag"`
}

type TokenData struct {
	MinimumAccountRange int64 `json:"minimumAccountRange"`
}

// PushFundsTransactionRequest resource credits (pushes) funds to a recipient's Visa account by initiating a
// financial message called an Original Credit Transaction (OCT).
type PushFundsTransactionRequest struct {
	Amount                        string                      `json:"amount"`
	SenderAddress                 string                      `json:"senderAddress"`
	LocalTransactionDateTime      string                      `json:"localTransactionDateTime"`
	PointOfServiceData            PointOfServiceData          `json:"pointOfServiceData"`
	RecipientPrimaryAccountNumber string                      `json:"recipientPrimaryAccountNumber"`
	ColombiaNationalServiceData   ColombiaNationalServiceData `json:"colombiaNationalServiceData"`
	CardAcceptor                  CardAcceptor                `json:"cardAcceptor"`
	SenderReference               string                      `json:"senderReference"`
	TransactionIdentifier         string                      `json:"transactionIdentifier"`
	AcquirerCountryCode           string                      `json:"acquirerCountryCode"`
	AcquiringBin                  string                      `json:"acquiringBin"`
	RetrievalReferenceNumber      string                      `json:"retrievalReferenceNumber"`
	SenderCity                    string                      `json:"senderCity"`
	SenderStateCode               string                      `json:"senderStateCode"`
	SystemsTraceAuditNumber       string                      `json:"systemsTraceAuditNumber"`
	SenderName                    string                      `json:"senderName"`
	BusinessApplicationId         string                      `json:"businessApplicationId"`
	SettlementServiceIndicator    string                      `json:"settlementServiceIndicator"`
	MerchantCategoryCode          string                      `json:"merchantCategoryCode"`
	TransactionCurrencyCode       string                      `json:"transactionCurrencyCode"`
	RecipientName                 string                      `json:"recipientName"`
	SenderCountryCode             string                      `json:"senderCountryCode"`
	SourceOfFundsCode             string                      `json:"sourceOfFundsCode"`
	SenderAccountNumber           string                      `json:"senderAccountNumber"`
}

type PushFundsTransactionResponse struct {
	TransactionIdentifier     int64                    `json:"transactionIdentifier"`
	ActionCode                string                   `json:"actionCode"`
	ResponseCode              string                   `json:"responseCode"`
	TransmissionDateTime      string                   `json:"transmissionDateTime"` // Format: yyyy-MM-ddTHH:mm:ss.SSS
	ApprovalCode              string                   `json:"approvalCode"`
	DeferredOCTData           DeferredOCTData          `json:"deferredOCTData"`
	FeeProgramIndicator       string                   `json:"feeProgramIndicator"`
	Last4ofPAN                int64                    `json:"last4OfPAN"`
	MerchantVerificationValue string                   `json:"merchantVerificationValue"`
	NetworkId                 int64                    `json:"networkId"`
	OriginalActionCode        string                   `json:"originalActionCode"`
	PrepaidBalance            string                   `json:"prepaidBalance"`
	PrepaidBalanceCurrency    string                   `json:"prepaidBalanceCurrency"`
	RetrievalReferenceNumber  string                   `json:"retrievalReferenceNumber"`
	StatusIdentifier          string                   `json:"statusIdentifier"`
	VauRTAuthReplacementData  VauRTAuthReplacementData `json:"vauRTAuthReplacementData"`
	SettlementFlags           SettlementFlags          `json:"settlementFlags"`
}

type PullFundsTransactionResponse struct {
	TransactionIdentifier                    int64                    `json:"transactionIdentifier"`
	ActionCode                               string                   `json:"actionCode"`
	ApprovalCode                             string                   `json:"approvalCode"`
	ResponseCode                             string                   `json:"responseCode"`
	TransmissionDateTime                     string                   `json:"transmissionDateTime"` // Format: yyyy-MM-ddTHH:mm:ss.SSS
	CavvResultCode                           string                   `json:"cavvResultCode"`
	SettlementFlags                          SettlementFlags          `json:"settlementFlags"`
	CpsAuthorizationCharacteristicsIndicator string                   `json:"cpsAuthorizationCharacteristicsIndicator"`
	CustomerReference                        string                   `json:"customerReference"`
	FeeProgramIndicator                      string                   `json:"feeProgramIndicator"`
	Last4ofPAN                               int64                    `json:"last4OfPAN"`
	MemberComments                           string                   `json:"memberComments"`
	MerchantVerificationValue                string                   `json:"merchantVerificationValue"`
	NetworkId                                int64                    `json:"networkId"`
	OriginalActionCode                       string                   `json:"originalActionCode"`
	PointOfServiceData                       PointOfServiceData       `json:"pointOfServiceData"`
	RecipientIdentificationNumberIndividual  string                   `json:"recipientIdentificationNumberIndividual"`
	ReimbursementAttribute                   string                   `json:"reimbursementAttribute"`
	StatusIdentifier                         string                   `json:"statusIdentifier"`
	TokenData                                TokenData                `json:"tokenData"`
	VauRTAuthReplacementData                 VauRTAuthReplacementData `json:"vauRTAuthReplacementData"`
}
