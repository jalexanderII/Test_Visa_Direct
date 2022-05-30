package models

import (
	"fmt"
	"strconv"
	"time"
)

type CountryCode int64

type BusinessApplicationCode string

// RetrievalReferenceNumber is a value used to tie together service calls related to a single financial transaction.
// When passing Account Funding Transaction (AFT) and Original Credit Transaction (OCT) methods,
// this value must differ between the two methods. When passing the Account Funding Transaction Reversal (AFTR) method,
// this value must match the retrievalReferenceNumber previously passed with the AFT method for this transaction.
type RetrievalReferenceNumber string

// GenerateRetrievalReferenceNumber will create a RetrievalReferenceNumber using the recommended Format: ydddhhnnnnnn
// The first fours digits must be a valid yddd date in the Julian date format, where the first digit = 0-9
// (last digit of current year) and the next three digits = 001-366 (number of the day in the year).
// hh can be the two digit hour in a 24-hour clock (00-23) during which the transaction is performed.
// nnnnnn can be the systemsTraceAuditNumber or any 6-digit number.
func GenerateRetrievalReferenceNumber(datetime time.Time, systemsTraceAuditNumber int) RetrievalReferenceNumber {
	yrday := fmt.Sprintf("%03d", datetime.YearDay())
	year := strconv.Itoa(datetime.Year())
	yearLastDigit := year[len(year)-1:]
	hour := fmt.Sprintf("%02d", datetime.Hour())
	response := fmt.Sprintf("%s%s%s%d", yearLastDigit, yrday, hour, systemsTraceAuditNumber)
	return RetrievalReferenceNumber(response)
}

type MotoECICode string

type PanEntryModeCode int32

type PosConditionCode int32

type PosEnvironment string

type AccountType string

type CPSIndicator string

type MessageReasonCode int64

const (
	// ResubmissionTransaction – A merchant performs a resubmission in cases where it requested an authorization, but
	// received a decline due to insufficient funds after it has already delivered the goods or services to the
	// cardholder. Merchants in such scenarios can resubmit the request to recover outstanding debt from cardholders
	ResubmissionTransaction MessageReasonCode = 3901
	// DelayedChargesTransaction – Delayed charge transaction is performed to process a supplemental account charge
	// after original services have been rendered and respective payment has been processed. Relevant merchant segments
	// are limited to vehicle rental, lodging, cruise lines, and other rentals.
	DelayedChargesTransaction MessageReasonCode = 3902
	// ReauthorizationTransaction – A merchant initiates a reauthorization when the completion or fulfillment of the
	// original order or service extends beyond the authorization validity limit set by Visa.
	// There are two common reauthorization scenarios:
	// • Split or delayed shipments at eCommerce retailers. A split shipment occurs when not all the goods ordered are
	// available for shipment at the time of purchase. If the fulfillment of the goods takes place after the
	// authorization validity limit set by Visa, eCommerce merchants perform a separate authorization to ensure
	// that consumer funds are available.
	// • Extended stay hotels, car rentals, and cruise lines. A reauthorization is used for stays, voyages, and/or
	// rentals that extend beyond the authorization validity period set by Visa.
	ReauthorizationTransaction MessageReasonCode = 3903
	// NoShowTransaction – Cardholders can use their Visa cards to make a guaranteed reservation with certain merchant
	// segments. A guaranteed reservation ensures that the reservation will be honored and allows a merchant to perform
	// a no-show transaction to charge the cardholder a penalty according to the merchant’s cancellation policy.
	NoShowTransaction MessageReasonCode = 3904
)

const (
	RequestsParticipation CPSIndicator = "Y"
)
const (
	NotApplicable     AccountType = "00"
	SavingAccount     AccountType = "10"
	CheckingAccount   AccountType = "20"
	CreditCardAccount AccountType = "30"
	UniversalAccount  AccountType = "40"
)
const (
	CredentialOnFilePosEnvironment PosEnvironment = "C"
	Installment                    PosEnvironment = "I"
	PeriodicBilling                PosEnvironment = "R"
)
const (
	NormalTransaction                                  PosConditionCode = 0
	CustomerNotPresent                                 PosConditionCode = 1
	UnattendedCardholderActivated                      PosConditionCode = 2
	MerchantSuspicious                                 PosConditionCode = 3
	CustomerPresentCardNotPresent                      PosConditionCode = 5
	PreauthorizedRequest                               PosConditionCode = 6
	MailTelephoneRecurringAdvanceInstallmentOrder      PosConditionCode = 8
	SuspectedFraud                                     PosConditionCode = 11
	Security                                           PosConditionCode = 12
	DisputeResponseFinancial                           PosConditionCode = 13
	DisputeFinancial                                   PosConditionCode = 17
	AddressCVV2AccountVerificationWithoutAuthorization PosConditionCode = 51
	ReservedForFutureUsePosConditionCode               PosConditionCode = 52
	DisputeFinancialReversal                           PosConditionCode = 54
	PublicNetworkEcommerceRequest                      PosConditionCode = 59
	CardPresentMagneticStripeCannotRead                PosConditionCode = 71
)

const (
	UnknownTerminalNotUsed                  PanEntryModeCode = 0
	ManualKeyEntry                          PanEntryModeCode = 1
	MagneticStripeRead                      PanEntryModeCode = 2
	OpticalCode                             PanEntryModeCode = 3
	ReservedForFutureUsePanEntryModeCode    PanEntryModeCode = 4
	VSDCChipRead                            PanEntryModeCode = 5
	QVSDCContactlessDeviceRead              PanEntryModeCode = 7
	CredentialOnFilePanEntryModeCode        PanEntryModeCode = 10
	MagneticStripeReadWithTrackDataIncluded PanEntryModeCode = 90
	MagneticStripeContactlessDeviceRead     PanEntryModeCode = 91
	IntegratedCircuitCardRead               PanEntryModeCode = 95
)

const (
	NotMailOrderTelephoneOrder          MotoECICode = "0"
	SingleTransactionMailPhoneOrder     MotoECICode = "1"
	RecurringTransaction                MotoECICode = "2"
	InstallmentPayment                  MotoECICode = "3"
	UnknownClassificationMailOrder      MotoECICode = "4"
	SecureElectronicCommerceTransaction MotoECICode = "5"
	NonAuthenticated3DSecureTransaction MotoECICode = "6"
	NonAuthenticatedSecurityTransaction MotoECICode = "7"
	NonSecureTransaction                MotoECICode = "8"
)

const (
	Unknown CountryCode = -1
	USA     CountryCode = 840
	DEU     CountryCode = 276 // Germany
)

type RecipientIdentificationNumber string

const (
	RecipientAccountToAccount           RecipientIdentificationNumber = "AA"
	RecipientPersonToPerson             RecipientIdentificationNumber = "PP"
	RecipientTopUpPrepaidReload         RecipientIdentificationNumber = "TU"
	RecipientBankInitiatedMoneyTransfer RecipientIdentificationNumber = "BI"
	RecipientWalletTransfer             RecipientIdentificationNumber = "WT"
	RecipientFundsTransfer              RecipientIdentificationNumber = "FT"
)

const (
	AccountToAccount               BusinessApplicationCode = "AA"
	BusinessToBusiness             BusinessApplicationCode = "BB"
	BankInitiatedMoneyTransfer     BusinessApplicationCode = "BI"
	CardBillPayment                BusinessApplicationCode = "CP"
	GeneralFundsDisbursement       BusinessApplicationCode = "FD"
	FundsTransfer                  BusinessApplicationCode = "FT"
	GovernmentDisbursement         BusinessApplicationCode = "GD"
	NonOnlineGamblingPayment       BusinessApplicationCode = "GP"
	LoyaltyAndOffers               BusinessApplicationCode = "LO"
	NonCardBillPayment             BusinessApplicationCode = "BP"
	MerchantInitiatedMoneyTransfer BusinessApplicationCode = "MI"
	CashIn                         BusinessApplicationCode = "CI"
	CashOut                        BusinessApplicationCode = "CO"
	FaceToFaceMerchantPayment      BusinessApplicationCode = "MP"
	MerchantDisbursement           BusinessApplicationCode = "MD"
	OnlineGamblingPayout           BusinessApplicationCode = "OG"
	PayrollOrPensionDisbursement   BusinessApplicationCode = "PD"
	PersonToPerson                 BusinessApplicationCode = "PP"
	TopUpPrepaidReload             BusinessApplicationCode = "TU"
	WalletTransfer                 BusinessApplicationCode = "WT"
	PaymentForGoodsAndServices     BusinessApplicationCode = "PS"
	CashDeposit                    BusinessApplicationCode = "CD"
)

func (c CountryCode) String() string {
	return strconv.Itoa(int(c))
}

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
	// 3-character alpha country code
	Country string `json:"country"`
	// 3-digit numeric FIPS county code of the money transfer operator/Originator.
	// Required if country is "USA".
	County string `json:"county"`
	// State or province of the money transfer operator/Originator.
	// Required if cardAcceptor:address:country is "USA" or "CAN".
	State string `json:"state"`
	// Zip/Postal code of the money transfer operator/Originator.
	// Required if cardAcceptor:address:country is "US" or "CA".
	ZipCode string `json:"zipCode"`
}

type PaymentFacilitator struct {
	// Marketplace ID or Payment Facilitator's ID.
	// This field is conditionally required when a payment facilitator is involved.
	// [ 1 .. 11 ] characters
	Id   string `json:"id"`
	Name string `json:"name"`
	// Sub-Merchant ID containing the sponsored merchant ID.
	// This field is conditionally required when a payment facilitator is involved.
	// [ 1 .. 15 ] characters
	SubMerchantId string `json:"subMerchantId"`
}

type CardAcceptor struct {
	Address Address `json:"address"`
	// An identifier for the card acceptor (Visa Direct Originator).
	// This value should be unique for each originator for whom you are sending transactions.
	// [ 1 .. 15 ] characters
	IdCode string `json:"idCode"`
	// name of the originator/money transfer operator.
	Name string `json:"name"`
	// The identifier for the terminal at a card acceptor location.
	// If sending transactions from a card not present environment, use the same value for all transactions.
	// [ 1 .. 8 ] characters
	TerminalId string `json:"terminalId"`
	// Acceptor’s legal business name associated with the card acceptor identification code for AFT transactions.
	// LegalBusinessName  string             `json:"legalBusinessName,omitempty"`
	// PaymentFacilitator PaymentFacilitator `json:"paymentFacilitator,omitempty"`
}

type AddressVerificationData struct {
	Street     string `json:"street"`
	PostalCode string `json:"postalCode"`
}

type PointOfServiceData struct {
	// Identifies the level of security used in an electronic commerce transaction over an open network
	MotoECIIndicator MotoECICode `json:"motoECIIndicator"`
	// A 2-digit code that identifies the method used to enter the cardholder account number and card expiration date.
	// This code specifies whether the entire magnetic stripe is included in an authorization or financial request.
	PanEntryMode PanEntryModeCode `json:"panEntryMode"`
	// Contains a code identifying transaction conditions at the point of sale or point of service.
	// For messages that follow an original request, this code identifies the type of processing being done.
	PosConditionCode PosConditionCode `json:"posConditionCode"`
	// This field is required to identify whether a transaction is merchant-initiated.
	PosEnvironment PosEnvironment `json:"posEnvironment,omitempty"`
	// Cryptocurrency indicator with the value of “7” can be used to identify the purchase of cryptocurrency
	// SpecialConditionIndicatorMerchant string `json:"specialConditionIndicatorMerchant,omitempty"`
}

type MagneticStripeData struct {
	Track1Data string `json:"track1Data"`
	Track2Data string `json:"track2Data,omitempty"`
}

type MerchantVerificationValue struct {
	MVVAcquirerAssigned string `json:"mvvAcquirerAssigned"`
	MVVVisaAssigned     string `json:"mvvVisaAssigned"`
}

type SecurityRelatedControlInfo struct {
	PinBlockFormatCode int64 `json:"pinBlockFormatCode"`
	ZoneKeyIndex       int64 `json:"zoneKeyIndex"`
}

type PinData struct {
	PinDataBlock               string                     `json:"pinDataBlock"`
	SecurityRelatedControlInfo SecurityRelatedControlInfo `json:"securityRelatedControlInfo"`
}

type SettlementServiceIndicator int32

const (
	InternationalSettlement SettlementServiceIndicator = 0
	VIPToDecide             SettlementServiceIndicator = 9
	NationalSettlement      SettlementServiceIndicator = 8
)

type SharingGroupCode string

const (
	AccelExchange SharingGroupCode = "E"
	CU24          SharingGroupCode = "C"
	Interlink     SharingGroupCode = "G"
	Maestro       SharingGroupCode = "8"
	NYCE18        SharingGroupCode = "Y"
	NYCE27        SharingGroupCode = "F"
	Pulse9        SharingGroupCode = "S"
	Pulse17       SharingGroupCode = "L"
	Pulse19       SharingGroupCode = "H"
	Star8         SharingGroupCode = "N"
	Star10        SharingGroupCode = "W"
	Star11        SharingGroupCode = "Z"
	Star12        SharingGroupCode = "Q"
	Star15        SharingGroupCode = "M"
	VisaPLUS      SharingGroupCode = "V"
)

type SourceOfFundsCode string

const (
	VisaCredit          SourceOfFundsCode = "01"
	VisaDebit           SourceOfFundsCode = "02"
	VisaPrepaid         SourceOfFundsCode = "03"
	Cash                SourceOfFundsCode = "04"
	NonVisaDebitDeposit SourceOfFundsCode = "05"
	NonVisaCredit       SourceOfFundsCode = "06"
)

type VauFlag string

const PerformVAU VauFlag = "Y"

type IdOwnerType string

const (
	Business   IdOwnerType = "B"
	Individual IdOwnerType = "I"
)

type IdType string

const (
	DateOfBirth                       IdType = "BTHD"
	CustomerIdentificationUnspecified IdType = "CUID"
	NationalIdentification            IdType = "NTID"
	PassportNumber                    IdType = "PASN"
	DriverLicense                     IdType = "DRLN"
	TaxIdentification                 IdType = "TXIN"
	CompanyRegistrationNumber         IdType = "CPNY"
	ProxyIdentification               IdType = "PRXY"
	SocialSecurityNumber              IdType = "SSNB"
	AlienRegistrationNumber           IdType = "ARNB"
	LawEnforcementIdentification      IdType = "LAWE"
	MilitaryIdentification            IdType = "MILI"
	TravelIdentificationNonPassport   IdType = "TRVL"
	Email                             IdType = "EMAL"
	PhoneNumber                       IdType = "PHON"
)

// IdentificationList contains:
// [idIssueCountry , idNumber , idOwnerType , idType]
// For a given instance of identificationList[], a minimum of idType and idNumber fields should be provided, else the ID information will not be forwarded to the issuer.
type IdentificationList []string

type SenderAdditionalData struct {
	IdentificationList IdentificationList `json:"identificationList"`
}

type RecipientAdditionalData struct {
	IdentificationList IdentificationList `json:"identificationList"`
}

// PullFundsTransactionRequest Resource debits (pulls) funds from a sender's Visa account (in preparation for
// pushing funds to a recipient's account) by initiating a financial message called an Account Funding Transaction (AFT)
type PullFundsTransactionRequest struct {
	// Use a 3-digit numeric country code for the country of the BIN under which your Visa Direct solution is registered. .
	AcquirerCountryCode CountryCode `json:"acquirerCountryCode"`
	// The Bank Identification Number (BIN) under which your Visa Direct is registered.
	AcquiringBin int `json:"acquiringBin"`
	// The amount of the transaction, inclusive of all fees you assess for the transaction, including currency
	// conversion fees. If the originator is populating the surcharge or foreignExchangeFeeTransaction field,
	// they must be included in the amount field.
	Amount float32 `json:"amount"`
	// Identifies the programs' business application type for VisaNet transaction processing
	// For Money Transfer, AA applies to transactions where the sender and recipient are the same person and
	// PP applies to transactions where the sender and recipient are not the same person.
	BusinessApplicationId BusinessApplicationCode `json:"businessApplicationId"`
	CardAcceptor          CardAcceptor            `json:"cardAcceptor"`
	// This field contains the local date and time of the transaction takes place
	// originated from merchant, service provider or acquirer. Format: YYYY-MM-DDThh:mm:ss
	LocalTransactionDateTime string `json:"localTransactionDateTime"`
	// If provided, then the value overrides the one present in onboarding data.
	// If the merchantCategoryCode value is not populated in onboarding data then this field is mandatory.
	MerchantCategoryCode int64 `json:"merchantCategoryCode,omitempty"`
	// Contains a code identifying transaction conditions at the point-of-sale or point of service.
	// For a CardPresent Transactions, this field is required.
	PointOfServiceData       PointOfServiceData       `json:"pointOfServiceData,omitempty"`
	RetrievalReferenceNumber RetrievalReferenceNumber `json:"retrievalReferenceNumber"`
	// expiration date for the sender's Visa account number or token in senderPrimaryAccountNumber. Format: YYYY-MM
	SenderCardExpiryDate string `json:"senderCardExpiryDate"`
	// 3-character alpha or numeric currency code
	SenderCurrencyCode string `json:"senderCurrencyCode"`
	// This is a 16-digit PAN or token of the sender's account.
	// [ 13 .. 19 ] characters
	SenderPrimaryAccountNumber string `json:"senderPrimaryAccountNumber"`
	//  A unique 6-digit value should be used for each API method. However, when passing the (AFTR) method, this value must
	//  match the systemsTraceAuditNumber previously passed with the AFT method for the current transaction.
	SystemsTraceAuditNumber string `json:"systemsTraceAuditNumber"`
	// account type of the senderPrimaryAccountNumber in the request.
	AccountType AccountType `json:"accountType"`
	// Address verification is required for an AFT transaction to qualify for CPS.
	AddressVerificationData   AddressVerificationData `json:"addressVerificationData,omitempty"`
	ArgentinaReimbursementFee float64                 `json:"argentinaReimbursementFee,omitempty"`
	// The cardCvv2Value value provided by the account holder for the senderPrimaryAccountNumber in the request.
	CardCvv2Value string `json:"cardCvv2Value,omitempty"`
	// The Cardholder Authentication Verification Value (CAVV) is a value generated by an Access Control Server (ACS)
	// and signed by the Issuer using account and password information of cardholders registered for the Verified by
	// Visa (also known as Visa Secure) program. This field should be in hexbinary format.
	Cavv                        string                      `json:"cavv,omitempty"`
	ColombiaNationalServiceData ColombiaNationalServiceData `json:"colombiaNationalServiceData,omitempty"`
	// Request for CPS authorization.
	CpsAuthorizationCharacteristicsIndicator CPSIndicator `json:"cpsAuthorizationCharacteristicsIndicator,omitempty"`
	FeeProgramIndicator                      string       `json:"feeProgramIndicator,omitempty"`
	// The sender's foreign exchange markup fee
	ForeignExchangeFeeTransaction float64            `json:"foreignExchangeFeeTransaction"`
	MagneticStripeData            MagneticStripeData `json:"magneticStripeData,omitempty"`
	MemberComments                string             `json:"memberComments,omitempty"`
	// Uniquely identifier for originator after they sign up to send Push Payment Gateway transactions
	MerchantPseudoAbaNumber string `json:"merchantPseudoAbaNumber,omitempty"`
	// This is an alphanumeric value that carries the merchant’s unique identification number
	// issued by the government or an authorized national entity.
	MerchantReference         string                    `json:"merchantReference,omitempty"`
	MerchantVerificationValue MerchantVerificationValue `json:"merchantVerificationValue,omitempty"`
	MessageReasonCode         MessageReasonCode         `json:"messageReasonCode,omitempty"`
	// IRF fees
	NationalReimbursementFee   float64 `json:"nationalReimbursementFee,omitempty"`
	OptionalResponseParameters string  `json:"optionalResponseParameters,omitempty"`
	OriginalTransactionId      int64   `json:"originalTransactionId,omitempty"`
	PinData                    PinData `json:"pinData,omitempty"`
	// For a CardPresent Transactions, this field is required.
	PointOfServiceCapability PointOfServiceCapability `json:"pointOfServiceCapability,omitempty"`
	PurposeOfPayment         string                   `json:"purposeOfPayment,omitempty"`
	RecipientAdditionalData  RecipientAdditionalData  `json:"recipientAdditionalData,omitempty"`
	RecipientAddressLine1    string                   `json:"recipientAddressLine1,omitempty"`
	RecipientAddressLine2    string                   `json:"recipientAddressLine2,omitempty"`
	RecipientBuildingNumber  string                   `json:"recipientBuildingNumber,omitempty"`
	RecipientCity            string                   `json:"recipientCity,omitempty"`
	RecipientCountryCode     string                   `json:"recipientCountryCode,omitempty"`
	RecipientFirstName       string                   `json:"recipientFirstName,omitempty"`
	// This is an alphanumeric value that carries the recipient's identification number issued to the recipient by
	// the government or an authorized national entity. This field is to be used if the recipient
	// is a business (e.g. Disbursements)
	RecipientIdentificationNumberBusiness RecipientIdentificationNumber `json:"recipientIdentificationNumberBusiness,omitempty"`
	// This is an alphanumeric value that carries the recipient's identification number issued to the recipient
	// by the government or an authorized national entity. This field is to be used if the recipient
	// is an Individual (e.g. P2P payments)
	RecipientIdentificationNumberIndividual RecipientIdentificationNumber `json:"recipientIdentificationNumberIndividual,omitempty"`
	RecipientLastName                       string                        `json:"recipientLastName,omitempty"`
	RecipientMiddleInitial                  string                        `json:"recipientMiddleInitial,omitempty"`
	RecipientMiddleName                     string                        `json:"recipientMiddleName,omitempty"`
	// Recipient name is required for cross-border enhanced money transfer AFTs.
	RecipientName       string `json:"recipientName,omitempty"`
	RecipientPostalCode string `json:"recipientPostalCode,omitempty"`
	// Required if RecipientCountryCode is either 124(CAN) or 840(USA)
	RecipientState                string               `json:"recipientState,omitempty"`
	RecipientStreetName           string               `json:"recipientStreetName,omitempty"`
	RecipientSubDivisionMinorCode string               `json:"recipientSubDivisionMinorCode,omitempty"`
	RiskAssessmentData            RiskAssessmentData   `json:"riskAssessmentData,omitempty"`
	SenderAccountNumber           string               `json:"senderAccountNumber,omitempty"`
	SenderAdditionalData          SenderAdditionalData `json:"senderAdditionalData,omitempty"`
	SenderCity                    string               `json:"senderCity,omitempty"`
	SenderCountryCode             string               `json:"senderCountryCode,omitempty"`
	SenderFirstName               string               `json:"senderFirstName,omitempty"`
	SenderLastName                string               `json:"senderLastName,omitempty"`
	SenderMiddleInitial           string               `json:"senderMiddleInitial,omitempty"`
	SenderMiddleName              string               `json:"senderMiddleName,omitempty"`
	// If the transaction is a money transfer and cross-border , a pre-paid load or credit card bill pay , or
	// U.S. domestic, this field must contain the sender's name. If the transaction is a funds disbursement and
	// cross-border or U.S. domestic, this field must contain either the name of the merchant or
	// government entity sending the funds' disbursement.
	// Recommended Format: Last Name/Family Surname 1 + + Space + First Name/Given Name + Space +
	// Middle Initial or Middle name (optional) + space
	SenderName       string `json:"senderName,omitempty"`
	SenderPostalCode string `json:"senderPostalCode,omitempty"`
	// If the transaction is a money transfer, pre-paid load, or credit card bill pay, and if the sender intends to
	// fund the transaction with a non-financial instrument (for example, cash), a reference number unique to
	// the sender is required. If the transaction is a funds' disbursement, the field is required.
	SenderReference string `json:"senderReference,omitempty"`
	SenderStateCode string `json:"senderStateCode,omitempty"`
	// This flag enables the originator to request for a particular settlement service to be used
	// for settling the transaction.
	SettlementServiceIndicator SettlementServiceIndicator `json:"settlementServiceIndicator,omitempty"`
	SharingGroupCode           SharingGroupCode           `json:"sharingGroupCode,omitempty"`
	SourceOfFundsCode          SourceOfFundsCode          `json:"sourceOfFundsCode,omitempty"`
	Surcharge                  float64                    `json:"surcharge,omitempty"`
	// The Token Authentication Verification Value (TAVV) is a value generated using tokenized PAN by Visa Token
	// Service (VTS) and signed by the Issuer. This field should be in hexbinary format.
	//	Note: A token should be sent (instead of a PAN) in senderPrimaryAccountNumber field while
	//	sending a TAVV cryptogram.
	Tavv                   string  `json:"tavv,omitempty"`
	VauFlag                VauFlag `json:"vauFlag,omitempty"`
	VisaMerchantIdentifier string  `json:"visaMerchantIdentifier"`
}

type PointOfServiceCapability struct {
	// Valid values if card is present include 0, 2 and 9. If card is not present, valid value is 1.
	PosTerminalEntryCapability int32 `json:"posTerminalEntryCapability"`
	// Valid values if card is present include 0, 3 and 4. If card is not present, valid value is 5.
	PosTerminalType int32 `json:"posTerminalType"`
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

// PushFundsTransactionRequest resource credits (pushes) funds to a recipient's Visa accounts by initiating a
// financial message called an Original Credit Transaction (OCT).
type PushFundsTransactionRequest struct {
	// The amount of the transaction, inclusive of all fees you assess for the transaction, including currency
	// conversion fees. If the originator is populating the surcharge or foreignExchangeFeeTransaction field,
	// they must be included in the amount field.
	Amount        float32 `json:"amount"`
	SenderAddress string  `json:"senderAddress"`
	// This field contains the local date and time of the transaction takes place
	// originated from merchant, service provider or acquirer. Format: YYYY-MM-DDThh:mm:ss
	LocalTransactionDateTime string `json:"localTransactionDateTime"`
	// Contains a code identifying transaction conditions at the point-of-sale or point of service.
	// For a CardPresent Transactions, this field is required.
	PointOfServiceData            PointOfServiceData          `json:"pointOfServiceData,omitempty"`
	RecipientPrimaryAccountNumber string                      `json:"recipientPrimaryAccountNumber"`
	ColombiaNationalServiceData   ColombiaNationalServiceData `json:"colombiaNationalServiceData,omitempty"`
	CardAcceptor                  CardAcceptor                `json:"cardAcceptor"`
	// If the transaction is a money transfer, pre-paid load, or credit card bill pay, and if the sender intends to
	// fund the transaction with a non-financial instrument (for example, cash), a reference number unique to
	// the sender is required. If the transaction is a funds' disbursement, the field is required.
	SenderReference       string `json:"senderReference,omitempty"`
	TransactionIdentifier string `json:"transactionIdentifier"`
	// Use a 3-digit numeric country code for the country of the BIN under which your Visa Direct solution is registered. .
	AcquirerCountryCode CountryCode `json:"acquirerCountryCode"`
	// The Bank Identification Number (BIN) under which your Visa Direct is registered.
	AcquiringBin             int                      `json:"acquiringBin"`
	RetrievalReferenceNumber RetrievalReferenceNumber `json:"retrievalReferenceNumber"`
	SenderCity               string                   `json:"senderCity,omitempty"`
	SenderStateCode          string                   `json:"senderStateCode,omitempty"`
	//  A unique 6-digit value should be used for each API method. However, when passing the (AFTR) method, this value must
	//  match the systemsTraceAuditNumber previously passed with the AFT method for the current transaction.
	SystemsTraceAuditNumber string `json:"systemsTraceAuditNumber"`
	// If the transaction is a money transfer and cross-border , a pre-paid load or credit card bill pay , or
	// U.S. domestic, this field must contain the sender's name. If the transaction is a funds disbursement and
	// cross-border or U.S. domestic, this field must contain either the name of the merchant or
	// government entity sending the funds' disbursement.
	// Recommended Format: Last Name/Family Surname 1 + + Space + First Name/Given Name + Space +
	// Middle Initial or Middle name (optional) + space
	SenderName string `json:"senderName,omitempty"`
	// Identifies the programs' business application type for VisaNet transaction processing
	// For Money Transfer, AA applies to transactions where the sender and recipient are the same person and
	// PP applies to transactions where the sender and recipient are not the same person.
	BusinessApplicationId BusinessApplicationCode `json:"businessApplicationId"`
	// This flag enables the originator to request for a particular settlement service to be used
	// for settling the transaction.
	SettlementServiceIndicator SettlementServiceIndicator `json:"settlementServiceIndicator,omitempty"`
	// If provided, then the value overrides the one present in onboarding data.
	// If the merchantCategoryCode value is not populated in onboarding data then this field is mandatory.
	MerchantCategoryCode    int64       `json:"merchantCategoryCode,omitempty"`
	TransactionCurrencyCode CountryCode `json:"transactionCurrencyCode"`
	// Recipient name is required for cross-border enhanced money transfer AFTs.
	RecipientName       string            `json:"recipientName,omitempty"`
	SenderCountryCode   string            `json:"senderCountryCode,omitempty"`
	SourceOfFundsCode   SourceOfFundsCode `json:"sourceOfFundsCode,omitempty"`
	SenderAccountNumber string            `json:"senderAccountNumber,omitempty"`
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
