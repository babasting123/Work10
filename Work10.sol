
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DigitalCertificate {

    address public owner;

    uint256 public courseCount;
    uint256 public certificateCount;

    // ข้อมูลหลักสูตร
    struct Course {
        string courseId;
        string courseName;
        string description;
        bool exists;
    }

    // ข้อมูลใบรับรอง
    struct Certificate {
        string certificateId;
        string courseId;
        address recipient;
        address issuer;
        uint256 issueDate;
        bytes32 documentHash;
        bool revoked;
        bool exists;
    }

    mapping(string => Course) private courses;

    mapping(string => Certificate) private certificates;

    mapping(address => string[]) private userCertificates;

    mapping(address => bool) public authorizedIssuers;

    // Events
    event CourseCreated(
        string courseId,
        string courseName
    );

    event CertificateIssued(
        string certificateId,
        address indexed recipient
    );

    event CertificateHashStored(
        string certificateId,
        bytes32 documentHash
    );

    event CertificateRevoked(
        string certificateId
    );

    event IssuerUpdated(
        address indexed issuer,
        bool authorized
    );

    constructor() {
        owner = msg.sender;
        authorizedIssuers[msg.sender] = true;
    }

    // ตรวจสอบสิทธิ์เจ้าของ
    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "Only owner"
        );
        _;
    }

    // ตรวจสอบสิทธิ์ผู้ออกใบรับรอง
    modifier onlyAuthorized() {
        require(
            authorizedIssuers[msg.sender],
            "Not authorized"
        );
        _;
    }

    // กำหนดสิทธิ์ผู้ออกใบรับรอง
    function setIssuer(
        address _issuer,
        bool _authorized
    ) public onlyOwner {

        require(
            _issuer != address(0),
            "Invalid address"
        );

        authorizedIssuers[_issuer] = _authorized;

        emit IssuerUpdated(
            _issuer,
            _authorized
        );
    }

    // =====================================
    // 1. ลงทะเบียนหลักสูตร
    // =====================================

    function createCourse(
        string memory _courseId,
        string memory _courseName,
        string memory _description
    ) public onlyOwner {

        require(
            bytes(_courseId).length > 0,
            "Invalid course ID"
        );

        require(
            bytes(_courseName).length > 0,
            "Invalid course name"
        );

        require(
            !courses[_courseId].exists,
            "Course ID already exists"
        );

        courses[_courseId] = Course(
            _courseId,
            _courseName,
            _description,
            true
        );

        courseCount++;

        emit CourseCreated(
            _courseId,
            _courseName
        );
    }

    // ตรวจสอบข้อมูลหลักสูตร
    function getCourse(
        string memory _courseId
    ) public view returns (Course memory) {

        require(
            courses[_courseId].exists,
            "Course not found"
        );

        return courses[_courseId];
    }

    // =====================================
    // 2. ออกใบรับรอง
    // =====================================

    function issueCertificate(
        string memory _certificateId,
        string memory _courseId,
        address _recipient
    ) public onlyAuthorized {

        require(
            bytes(_certificateId).length > 0,
            "Invalid certificate ID"
        );

        require(
            !certificates[_certificateId].exists,
            "Certificate ID already exists"
        );

        require(
            courses[_courseId].exists,
            "Course not found"
        );

        require(
            _recipient != address(0),
            "Invalid recipient"
        );

        certificates[_certificateId] = Certificate(
            _certificateId,
            _courseId,
            _recipient,
            msg.sender,
            block.timestamp,
            bytes32(0),
            false,
            true
        );

        userCertificates[_recipient].push(
            _certificateId
        );

        certificateCount++;

        emit CertificateIssued(
            _certificateId,
            _recipient
        );
    }

    // =====================================
    // 3. บันทึก Hash ของใบรับรอง
    // =====================================

    function storeCertificateHash(
        string memory _certificateId,
        bytes32 _documentHash
    ) public onlyAuthorized {

        Certificate storage cert =
            certificates[_certificateId];

        require(
            cert.exists,
            "Certificate not found"
        );

        require(
            !cert.revoked,
            "Certificate revoked"
        );

        require(
            msg.sender == cert.issuer ||
            msg.sender == owner,
            "Not certificate issuer"
        );

        require(
            _documentHash != bytes32(0),
            "Invalid hash"
        );

        require(
            cert.documentHash == bytes32(0),
            "Hash already stored"
        );

        cert.documentHash = _documentHash;

        emit CertificateHashStored(
            _certificateId,
            _documentHash
        );
    }

    // =====================================
    // 4. ตรวจสอบความถูกต้องของใบรับรอง
    // =====================================

    function verifyCertificate(
        string memory _certificateId
    ) public view returns (
        bool valid,
        string memory status
    ) {

        Certificate memory cert =
            certificates[_certificateId];

        if (!cert.exists) {
            return (false, "Certificate not found");
        }

        if (cert.revoked) {
            return (false, "Certificate revoked");
        }

        if (cert.documentHash == bytes32(0)) {
            return (false, "Hash not registered");
        }

        return (true, "Certificate valid");
    }

    // ตรวจสอบ Hash ว่าเอกสารตรงกับต้นฉบับหรือไม่
    function verifyHash(
        string memory _certificateId,
        bytes32 _documentHash
    ) public view returns (bool) {

        Certificate memory cert =
            certificates[_certificateId];

        return (
            cert.exists &&
            !cert.revoked &&
            cert.documentHash != bytes32(0) &&
            cert.documentHash == _documentHash
        );
    }

    // ดูรายละเอียดใบรับรอง
    function getCertificate(
        string memory _certificateId
    ) public view returns (Certificate memory) {

        require(
            certificates[_certificateId].exists,
            "Certificate not found"
        );

        return certificates[_certificateId];
    }

    // =====================================
    // 5. เพิกถอนใบรับรอง
    // =====================================

    function revokeCertificate(
        string memory _certificateId
    ) public onlyAuthorized {

        Certificate storage cert =
            certificates[_certificateId];

        require(
            cert.exists,
            "Certificate not found"
        );

        require(
            msg.sender == owner ||
            msg.sender == cert.issuer,
            "Not certificate issuer"
        );

        require(
            !cert.revoked,
            "Already revoked"
        );

        cert.revoked = true;

        emit CertificateRevoked(
            _certificateId
        );
    }

    // =====================================
    // 6. แสดงประวัติใบรับรองของตนเอง
    // =====================================

    function getMyCertificates()
        public
        view
        returns (string[] memory)
    {
        return userCertificates[msg.sender];
    }

    // สร้าง Hash จากข้อความสำหรับทดสอบ
    function generateHash(
        string memory _data
    ) public pure returns (bytes32) {

        return keccak256(
            abi.encodePacked(_data)
        );
    }
}
