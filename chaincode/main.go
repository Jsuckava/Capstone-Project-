package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/v2/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
)

type AcademicRecord struct {
	ID              string  `json:"id"`
	StudentHash     string  `json:"student_hash"`
	StudentID       string  `json:"student_id"`
	StudentNo       string  `json:"student_no"`
	StudentName     string  `json:"student_name"`
	Section         string  `json:"section"`
	YearLevel       string  `json:"year_level"`
	Course          string  `json:"course"`
	Program         string  `json:"program"`
	SubjectCode     string  `json:"subject_code"`
	SubjectTitle    string  `json:"subject_title"`
	Units           float64 `json:"units,omitempty"`
	Grade           string  `json:"grade"`
	Semester        string  `json:"semester"`
	SchoolYear      string  `json:"school_year"`
	Term            string  `json:"term"`
	FacultyID       string  `json:"faculty_id"`
	ProfessorName   string  `json:"professor_name"`
	Date            string  `json:"date"`
	Timestamp       string  `json:"timestamp"`
	SubmittedBy     string  `json:"submitted_by"`
	TransactionID   string  `json:"transaction_id"`
	TransactionHash string  `json:"transaction_hash"`
	IpfsCID         string  `json:"ipfs_cid"`
	University      string  `json:"university"`
	Status          string  `json:"status"`
	Note            string  `json:"note"`
	Version         int     `json:"version"`
}

type AuditRecord struct {
	ID              string   `json:"id"`
	EventType       string   `json:"event_type"`
	EntityID        string   `json:"entity_id"`
	ActorID         string   `json:"actor_id"`
	ActorRole       string   `json:"actor_role"`
	ChangedFields   []string `json:"changed_fields,omitempty"`
	Description     string   `json:"description,omitempty"`
	Timestamp       string   `json:"timestamp"`
	TransactionID   string   `json:"transaction_id"`
	TransactionHash string   `json:"transaction_hash"`
}

type SmartContract struct{}

const (
	statusIssued             = "Issued"
	statusReturned           = "Returned"
	statusCorrected          = "Corrected"
	statusDepartmentApproved = "DepartmentApproved"
	statusFinalized          = "Finalized"
)

func getSafeAttribute(stub shim.ChaincodeStubInterface, attrName string) (string, bool) {
	val, found, err := cid.GetAttributeValue(stub, attrName)
	if err != nil || !found {
		return "", false
	}
	return val, true
}

func roleMatchesMSP(mspID string, role string) bool {
	return (mspID == "RegistrarMSP" && (role == "registrar" || role == "student")) ||
		(mspID == "FacultyMSP" && role == "faculty") ||
		(mspID == "DepartmentMSP" && (role == "department_admin" || role == "deptAdmin"))
}

func authorizeGradeReader(stub shim.ChaincodeStubInterface) (string, *pb.Response) {
	mspID, err := cid.GetMSPID(stub)
	if err != nil {
		return "", shim.Error("Unable to determine the caller organization")
	}

	role, found := getSafeAttribute(stub, "role")
	if !found {
		return "", shim.Error("ABAC Denied: User role attribute not found")
	}

	if !roleMatchesMSP(mspID, role) {
		return "", shim.Error("OBAC/ABAC Denied: Role does not match the caller organization")
	}

	return role, nil
}

func getTransactionDate(stub shim.ChaincodeStubInterface) string {
	return getTransactionTime(stub).Format("2006-01-02")
}

func getTransactionTime(stub shim.ChaincodeStubInterface) time.Time {
	txTimestamp, err := stub.GetTxTimestamp()
	if err != nil || txTimestamp == nil {
		return time.Time{}
	}

	return time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC()
}

func getClientCommonName(stub shim.ChaincodeStubInterface) string {
	cert, err := cid.GetX509Certificate(stub)
	if err == nil && cert != nil {
		return cert.Subject.CommonName
	}
	clientID, _ := cid.GetID(stub)
	return clientID
}

func stampRecord(stub shim.ChaincodeStubInterface, record *AcademicRecord, actor string) {
	txTime := getTransactionTime(stub)
	txID := stub.GetTxID()
	record.TransactionID = txID
	record.TransactionHash = txID
	record.Timestamp = txTime.Format(time.RFC3339Nano)
	record.Date = txTime.Format("2006-01-02")
	if record.SubmittedBy == "" {
		record.SubmittedBy = actor
	}
	if record.StudentID == "" {
		record.StudentID = record.StudentNo
	}
	if record.StudentNo == "" {
		record.StudentNo = record.StudentID
	}
	if record.Program == "" {
		record.Program = record.Course
	}
	if record.Course == "" {
		record.Course = record.Program
	}
}

func (cc *SmartContract) Init(stub shim.ChaincodeStubInterface) *pb.Response {
	return shim.Success([]byte("OK"))
}

func (cc *SmartContract) Invoke(stub shim.ChaincodeStubInterface) *pb.Response {
	function, args := stub.GetFunctionAndParameters()

	switch function {
	case "InitLedger":
		return cc.initLedger(stub)
	case "IssueGrade":
		return cc.issueGrade(stub, args)
	case "IssueBatchGrades":
		return cc.issueBatchGrades(stub, args)
	case "ReturnGrade":
		return cc.returnGrade(stub, args)
	case "ReadGrade":
		return cc.readGrade(stub, args)
	case "UpdateGrade":
		return cc.updateGrade(stub, args)
	case "ApproveGrade":
		return cc.approveGrade(stub, args)
	case "FinalizeRecord":
		return cc.finalizeRecord(stub, args)
	case "GetAllGrades":
		return cc.getAllGrades(stub)
	case "GetGradeHistory":
		return cc.getGradeHistory(stub, args)
	case "GetStudentTransactions":
		return cc.getStudentTransactions(stub)
	case "CreateAuditEvent":
		return cc.createAuditEvent(stub, args)
	default:
		return shim.Error("Invalid function name")
	}
}

func (cc *SmartContract) initLedger(stub shim.ChaincodeStubInterface) *pb.Response {
	records := []AcademicRecord{
		{
			ID:            "GENESIS-001",
			StudentHash:   "genesis.student@plv.edu.ph",
			StudentID:     "23-0000",
			StudentNo:     "23-0000",
			StudentName:   "Genesis Student",
			Section:       "A",
			Course:        "BSIT",
			Program:       "BSIT",
			SubjectCode:   "IT-GENESIS",
			SubjectTitle:  "Genesis Record",
			Grade:         "1.00",
			Semester:      "1st Semester",
			SchoolYear:    "2023",
			FacultyID:     "system",
			ProfessorName: "System",
			Date:          "2023-01-01",
			University:    "PLV",
			Status:        statusFinalized,
			Version:       1,
		},
	}

	for _, record := range records {
		recordJSON, err := json.Marshal(record)
		if err != nil {
			return shim.Error(fmt.Sprintf("Failed to marshal genesis record: %v", err))
		}
		if err := stub.PutState(record.ID, recordJSON); err != nil {
			return shim.Error(fmt.Sprintf("Failed to put state for genesis record: %v", err))
		}
	}
	return shim.Success([]byte("Ledger Initialized Successfully with Genesis Data"))
}

func (cc *SmartContract) issueGrade(stub shim.ChaincodeStubInterface, args []string) *pb.Response {
	if len(args) < 1 {
		return shim.Error("Record data required")
	}

	mspID, err := cid.GetMSPID(stub)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get MSP ID: %v", err))
	}
	role, found := getSafeAttribute(stub, "role")
	if !found || !roleMatchesMSP(mspID, role) || (role != "faculty" && role != "department_admin" && role != "deptAdmin") {
		return shim.Error("ABAC Denied: User lacks the cryptographic 'faculty' or 'department_admin' role.")
	}

	var record AcademicRecord
	if err := json.Unmarshal([]byte(args[0]), &record); err != nil {
		return shim.Error(fmt.Sprintf("Invalid JSON input: %v", err))
	}

	if record.Grade == "" {
		return shim.Error("Grade field cannot be empty")
	}

	existing, err := stub.GetState(record.ID)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to read from state database: %v", err))
	}
	if existing != nil {
		return shim.Error("Record already exists")
	}

	submitterID := getClientCommonName(stub)
	record.FacultyID = submitterID
	record.SubmittedBy = submitterID
	record.Status = statusIssued
	record.Version = 1
	stampRecord(stub, &record, submitterID)

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to marshal record: %v", err))
	}
	if err := stub.PutState(record.ID, recordJSON); err != nil {
		return shim.Error(fmt.Sprintf("Failed to update state database: %v", err))
	}

	return shim.Success(recordJSON)
}

func (cc *SmartContract) issueBatchGrades(stub shim.ChaincodeStubInterface, args []string) *pb.Response {
	if len(args) < 1 {
		return shim.Error("Batch record data required")
	}

	mspID, err := cid.GetMSPID(stub)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get MSP ID: %v", err))
	}
	role, found := getSafeAttribute(stub, "role")
	if !found || !roleMatchesMSP(mspID, role) || (role != "faculty" && role != "department_admin" && role != "deptAdmin") {
		return shim.Error("ABAC Denied: User lacks the cryptographic 'faculty' or 'department_admin' role.")
	}

	var records []AcademicRecord
	err = json.Unmarshal([]byte(args[0]), &records)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal batch records: %v", err))
	}

	facultyID := getClientCommonName(stub)

	seen := map[string]bool{}
	processed := 0

	for _, record := range records {
		if record.ID == "" {
			continue
		}
		if seen[record.ID] {
			return shim.Error(fmt.Sprintf("Duplicate record ID in batch: %s", record.ID))
		}
		seen[record.ID] = true
		if record.Grade == "" {
			return shim.Error(fmt.Sprintf("Grade field cannot be empty for record %s", record.ID))
		}
		existing, err := stub.GetState(record.ID)
		if err != nil {
			return shim.Error(fmt.Sprintf("Failed to read from state database for record %s: %v", record.ID, err))
		}
		if existing != nil {
			return shim.Error(fmt.Sprintf("Record already exists: %s", record.ID))
		}
		record.FacultyID = facultyID
		record.SubmittedBy = facultyID
		record.Status = statusIssued
		if record.Version <= 0 {
			record.Version = 1
		}
		stampRecord(stub, &record, facultyID)
		recordJSON, err := json.Marshal(record)
		if err != nil {
			return shim.Error(fmt.Sprintf("Failed to marshal record %s: %v", record.ID, err))
		}
		if err := stub.PutState(record.ID, recordJSON); err != nil {
			return shim.Error(fmt.Sprintf("Failed to put state for record %s: %v", record.ID, err))
		}
		processed++
	}

	return shim.Success([]byte(fmt.Sprintf("Successfully processed %d records in batch", processed)))
}

func (cc *SmartContract) returnGrade(stub shim.ChaincodeStubInterface, args []string) *pb.Response {
	if len(args) < 2 {
		return shim.Error("Record ID and Revision Note required")
	}

	mspID, _ := cid.GetMSPID(stub)
	role, found := getSafeAttribute(stub, "role")
	isDepartmentAdmin := mspID == "DepartmentMSP" && (role == "department_admin" || role == "deptAdmin")
	isRegistrar := mspID == "RegistrarMSP" && role == "registrar"
	if !found || (!isDepartmentAdmin && !isRegistrar) {
		return shim.Error("OBAC/ABAC Denied: Only Department Admin or Registrar can return grades for revision")
	}

	recordID := args[0]
	note := args[1]

	recordJSON, err := stub.GetState(recordID)
	if err != nil || recordJSON == nil {
		return shim.Error("Record not found")
	}

	var record AcademicRecord
	if err := json.Unmarshal(recordJSON, &record); err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal record: %v", err))
	}

	record.Status = statusReturned
	record.Note = note
	record.Version++
	stampRecord(stub, &record, getClientCommonName(stub))

	updatedJSON, err := json.Marshal(record)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to marshal record: %v", err))
	}
	if err := stub.PutState(recordID, updatedJSON); err != nil {
		return shim.Error(fmt.Sprintf("Failed to update state database: %v", err))
	}

	return shim.Success(updatedJSON)
}

func (cc *SmartContract) readGrade(stub shim.ChaincodeStubInterface, args []string) *pb.Response {
	if len(args) < 1 {
		return shim.Error("ID required")
	}
	role, denied := authorizeGradeReader(stub)
	if denied != nil {
		return denied
	}

	recordJSON, err := stub.GetState(args[0])
	if err != nil || recordJSON == nil {
		return shim.Error("Record not found")
	}

	if role == "student" {
		var record AcademicRecord
		if err := json.Unmarshal(recordJSON, &record); err != nil {
			return shim.Error(fmt.Sprintf("Failed to unmarshal record: %v", err))
		}
		if !strings.EqualFold(record.StudentHash, getClientCommonName(stub)) {
			return shim.Error("ABAC Denied: Students may read only their own grade records")
		}
	}

	return shim.Success(recordJSON)
}

func (cc *SmartContract) updateGrade(stub shim.ChaincodeStubInterface, args []string) *pb.Response {
	if len(args) < 1 {
		return shim.Error("Updated record required")
	}

	role, denied := authorizeGradeReader(stub)
	if denied != nil || role == "student" {
		return shim.Error("ABAC Denied: Missing required role.")
	}

	var updated AcademicRecord
	if err := json.Unmarshal([]byte(args[0]), &updated); err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal updated record: %v", err))
	}

	if updated.Grade == "" {
		return shim.Error("Grade field cannot be empty")
	}

	existingJSON, err := stub.GetState(updated.ID)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to read from state database: %v", err))
	}
	if existingJSON == nil {
		return shim.Error("Record does not exist")
	}

	var existing AcademicRecord
	if err := json.Unmarshal(existingJSON, &existing); err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal existing record: %v", err))
	}

	submitterID, _ := cid.GetID(stub)
	var email string
	cert, err := cid.GetX509Certificate(stub)
	if err == nil && cert != nil {
		email = cert.Subject.CommonName
	}

	
	if existing.FacultyID != submitterID && existing.FacultyID != email {
		
		if updated.Status == statusReturned && (role == "department_admin" || role == "deptAdmin" || role == "registrar") {
			
		} else {
			return shim.Error("Only the original professor who issued the grade can update it")
		}
	}

	existing.Grade = updated.Grade
	if updated.Term != "" {
		existing.Term = updated.Term
	}
	existing.Status = statusCorrected
	existing.Version++
	stampRecord(stub, &existing, getClientCommonName(stub))

	recordJSON, _ := json.Marshal(existing)
	if err := stub.PutState(existing.ID, recordJSON); err != nil {
		return shim.Error(fmt.Sprintf("Failed to update state database: %v", err))
	}

	return shim.Success(recordJSON)
}

func (cc *SmartContract) approveGrade(stub shim.ChaincodeStubInterface, args []string) *pb.Response {
	if len(args) < 1 {
		return shim.Error("Record ID required")
	}

	mspID, _ := cid.GetMSPID(stub)
	role, found := getSafeAttribute(stub, "role")

	if !found {
		return shim.Error("ABAC Denied: User role attribute not found.")
	}

	isDeptAdmin := mspID == "DepartmentMSP" && role == "department_admin"
	isRegistrar := mspID == "RegistrarMSP" && role == "registrar"

	if !isDeptAdmin && !isRegistrar {
		return shim.Error("OBAC/ABAC Denied: Only Department Admin or Registrar can approve grades.")
	}

	recordJSON, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to read from state database: %v", err))
	}
	if recordJSON == nil {
		return shim.Error("Record not found")
	}

	var record AcademicRecord
	if err := json.Unmarshal(recordJSON, &record); err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal record: %v", err))
	}

	record.Status = statusDepartmentApproved
	record.Version++
	stampRecord(stub, &record, getClientCommonName(stub))
	updatedJSON, _ := json.Marshal(record)
	if err := stub.PutState(args[0], updatedJSON); err != nil {
		return shim.Error(fmt.Sprintf("Failed to update state database: %v", err))
	}

	return shim.Success(updatedJSON)
}

func (cc *SmartContract) finalizeRecord(stub shim.ChaincodeStubInterface, args []string) *pb.Response {
	if len(args) < 1 {
		return shim.Error("Record ID required")
	}

	mspID, _ := cid.GetMSPID(stub)
	role, found := getSafeAttribute(stub, "role")

	if !found {
		return shim.Error("ABAC Denied: User role attribute not found.")
	}

	isRegistrar := mspID == "RegistrarMSP" && role == "registrar"

	if !isRegistrar {
		return shim.Error("OBAC/ABAC Denied: Only the Master Registrar can finalize records to the ledger.")
	}

	recordJSON, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to read from state database: %v", err))
	}
	if recordJSON == nil {
		return shim.Error("Record not found")
	}

	var record AcademicRecord
	if err := json.Unmarshal(recordJSON, &record); err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal record: %v", err))
	}

	record.Status = statusFinalized
	record.Version++
	stampRecord(stub, &record, getClientCommonName(stub))
	updatedJSON, _ := json.Marshal(record)
	if err := stub.PutState(args[0], updatedJSON); err != nil {
		return shim.Error(fmt.Sprintf("Failed to update state database: %v", err))
	}

	return shim.Success(updatedJSON)
}

func (cc *SmartContract) getAllGrades(stub shim.ChaincodeStubInterface) *pb.Response {
	role, denied := authorizeGradeReader(stub)
	if denied != nil {
		return denied
	}

	querySelector := map[string]interface{}{
		"status":       map[string]string{"$ne": ""},
		"student_hash": map[string]string{"$ne": ""},
	}
	if role == "student" {
		querySelector["student_hash"] = getClientCommonName(stub)
	}
	queryBytes, err := json.Marshal(map[string]interface{}{"selector": querySelector})
	if err != nil {
		return shim.Error("Failed to build grade query: " + err.Error())
	}
	queryString := string(queryBytes)
	resultsIterator, err := stub.GetQueryResult(queryString)
	if err != nil {
		return shim.Error("Query failed: " + err.Error())
	}
	defer resultsIterator.Close()

	var records []AcademicRecord
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return shim.Error(fmt.Sprintf("Failed to get next iteration: %v", err))
		}
		var record AcademicRecord
		if err := json.Unmarshal(queryResponse.Value, &record); err != nil {
			return shim.Error(fmt.Sprintf("Failed to unmarshal record: %v", err))
		}
		records = append(records, record)
	}

	recordsJSON, _ := json.Marshal(records)
	return shim.Success(recordsJSON)
}

func gradeTransactionType(status string) string {
	switch strings.ToLower(status) {
	case strings.ToLower(statusIssued):
		return "GRADE_SUBMITTED"
	case strings.ToLower(statusReturned):
		return "GRADE_RETURNED"
	case strings.ToLower(statusCorrected):
		return "GRADE_REVISED"
	case strings.ToLower(statusDepartmentApproved):
		return "GRADE_APPROVED"
	case strings.ToLower(statusFinalized):
		return "GRADE_FINALIZED"
	default:
		return "GRADE_UPDATED"
	}
}

func (cc *SmartContract) getStudentTransactions(stub shim.ChaincodeStubInterface) *pb.Response {
	role, found := getSafeAttribute(stub, "role")
	mspID, mspErr := cid.GetMSPID(stub)
	if mspErr != nil || !found || mspID != "RegistrarMSP" || role != "student" {
		return shim.Error("ABAC Denied: Student transaction history requires the student role")
	}

	studentID := getClientCommonName(stub)
	queryBytes, err := json.Marshal(map[string]interface{}{
		"selector": map[string]interface{}{
			"student_hash": studentID,
			"status":       map[string]string{"$ne": ""},
		},
	})
	if err != nil {
		return shim.Error("Failed to build student query: " + err.Error())
	}

	results, err := stub.GetQueryResult(string(queryBytes))
	if err != nil {
		return shim.Error("Failed to query student records: " + err.Error())
	}
	defer results.Close()

	transactions := make([]map[string]interface{}, 0)
	for results.HasNext() {
		result, nextErr := results.Next()
		if nextErr != nil {
			return shim.Error("Failed to read student record: " + nextErr.Error())
		}
		history, historyErr := stub.GetHistoryForKey(result.Key)
		if historyErr != nil {
			return shim.Error("Failed to read student transaction history: " + historyErr.Error())
		}
		for history.HasNext() {
			entry, entryErr := history.Next()
			if entryErr != nil {
				history.Close()
				return shim.Error("Failed to read transaction entry: " + entryErr.Error())
			}
			if entry.IsDelete || len(entry.Value) == 0 {
				continue
			}
			var record AcademicRecord
			if unmarshalErr := json.Unmarshal(entry.Value, &record); unmarshalErr != nil {
				history.Close()
				return shim.Error("Failed to decode transaction entry: " + unmarshalErr.Error())
			}
			if !strings.EqualFold(record.StudentHash, studentID) {
				continue
			}
			transactions = append(transactions, map[string]interface{}{
				"transaction_id":   entry.TxId,
				"transaction_hash": entry.TxId,
				"transaction_type": gradeTransactionType(record.Status),
				"timestamp":        time.Unix(entry.Timestamp.Seconds, int64(entry.Timestamp.Nanos)).UTC().Format(time.RFC3339Nano),
				"record":           record,
			})
		}
		history.Close()
	}

	payload, err := json.Marshal(transactions)
	if err != nil {
		return shim.Error("Failed to encode student transactions: " + err.Error())
	}
	return shim.Success(payload)
}

func (cc *SmartContract) createAuditEvent(stub shim.ChaincodeStubInterface, args []string) *pb.Response {
	if len(args) < 1 {
		return shim.Error("Audit event data required")
	}
	mspID, _ := cid.GetMSPID(stub)
	role, found := getSafeAttribute(stub, "role")
	if !found || mspID != "RegistrarMSP" || role != "registrar" {
		return shim.Error("OBAC/ABAC Denied: Only Registrar identities can record lifecycle audit events")
	}

	var event AuditRecord
	if err := json.Unmarshal([]byte(args[0]), &event); err != nil {
		return shim.Error("Invalid audit event: " + err.Error())
	}
	allowed := map[string]bool{
		"REGISTRAR_ACCOUNT_CREATED": true,
		"REGISTRAR_ACCOUNT_UPDATED": true,
		"CURRICULUM_APPROVED":       true,
		"CURRICULUM_PUBLISHED":      true,
		"CURRICULUM_ARCHIVED":       true,
	}
	if !allowed[event.EventType] {
		return shim.Error("Unsupported audit event type")
	}
	if event.EntityID == "" || event.ActorID == "" {
		return shim.Error("Audit entity and actor are required")
	}

	txID := stub.GetTxID()
	event.ID = "AUDIT:" + txID
	event.TransactionID = txID
	event.TransactionHash = txID
	event.Timestamp = getTransactionTime(stub).Format(time.RFC3339Nano)
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return shim.Error("Failed to encode audit event: " + err.Error())
	}
	if err := stub.PutState(event.ID, eventJSON); err != nil {
		return shim.Error("Failed to store audit event: " + err.Error())
	}
	return shim.Success(eventJSON)
}

func (cc *SmartContract) getGradeHistory(stub shim.ChaincodeStubInterface, args []string) *pb.Response {
	if len(args) < 1 {
		return shim.Error("Record ID required")
	}
	recordID := args[0]

	role, denied := authorizeGradeReader(stub)
	if denied != nil || role == "student" {
		return shim.Error("ABAC Denied: Students cannot view the full audit history.")
	}
	if role == "faculty" {
		currentJSON, readErr := stub.GetState(recordID)
		if readErr != nil || currentJSON == nil {
			return shim.Error("Record not found")
		}
		var current AcademicRecord
		if err := json.Unmarshal(currentJSON, &current); err != nil {
			return shim.Error("Failed to decode current record: " + err.Error())
		}
		if !strings.EqualFold(current.FacultyID, getClientCommonName(stub)) {
			return shim.Error("ABAC Denied: Faculty may view only the history of grades they submitted")
		}
	}

	resultsIterator, err := stub.GetHistoryForKey(recordID)
	if err != nil {
		return shim.Error("Error retrieving grade history: " + err.Error())
	}
	defer resultsIterator.Close()

	var history []map[string]interface{}
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return shim.Error("Error processing history iteration: " + err.Error())
		}

		var value map[string]interface{}
		if len(response.Value) > 0 {
			err = json.Unmarshal(response.Value, &value)
			if err != nil {
				return shim.Error("Error unmarshalling history value: " + err.Error())
			}
		}

		historyRecord := map[string]interface{}{
			"txId":      response.TxId,
			"timestamp": time.Unix(response.Timestamp.Seconds, int64(response.Timestamp.Nanos)).UTC().Format(time.RFC3339Nano),
			"isDelete":  response.IsDelete,
			"value":     value,
		}
		history = append(history, historyRecord)
	}

	historyJSON, _ := json.Marshal(history)
	return shim.Success(historyJSON)
}

func main() {
	fmt.Println("[CHAINCODE] Starting registrar chaincode...")

	tlsDisabled := os.Getenv("CHAINCODE_TLS_DISABLED") == "true"
	ccID := os.Getenv("CHAINCODE_ID")
	address := os.Getenv("CHAINCODE_SERVER_ADDRESS")

	fmt.Println("[CHAINCODE] Config: TLS=", !tlsDisabled, " ID=", ccID, " Address=", address)

	server := &shim.ChaincodeServer{
		CCID:    ccID,
		Address: address,
		CC:      new(SmartContract),
	}

	if tlsDisabled {
		fmt.Println("[CHAINCODE] TLS DISABLED")
		server.TLSProps = shim.TLSProperties{Disabled: true}
	} else {
		fmt.Println("[CHAINCODE] TLS ENABLED")
		server.TLSProps = shim.TLSProperties{
			Disabled: false,
			Key:      readFile(os.Getenv("CHAINCODE_TLS_KEY_FILE")),
			Cert:     readFile(os.Getenv("CHAINCODE_TLS_CERT_FILE")),
		}
	}

	fmt.Println("[CHAINCODE] Starting server...")
	if err := server.Start(); err != nil {
		log.Fatalf("[CHAINCODE] Server start error: %v", err)
	}
	fmt.Println("[CHAINCODE] Server started successfully")
}

func readFile(path string) []byte {
	if path == "" {
		return nil
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		files, readDirErr := os.ReadDir(path)
		if readDirErr != nil {
			log.Fatalf("Failed to read directory %s: %v", path, readDirErr)
		}
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), "_sk") {
				path = filepath.Join(path, f.Name())
				break
			}
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read file content from %s: %v", path, err)
	}
	return content
}
