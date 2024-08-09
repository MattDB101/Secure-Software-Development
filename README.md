
#Introduction
This was my final project whilst undertaking level 9 course in Secure Software Development. 
The prescribed task was to plan with the use of JIRA and then subsequently create a login & file upload mechanism with role based access control. 
Privilged users would be able to access a panel showing recently uploaded files metadata, whilst non-privileged users would only be able to access to file upload portal.

This project was focused solely on the security aspects of such a system.
The technology chosen to implement this was Node.js with Express and MongoDB as a datastore.
These technologies were chosen both because of the vast quantity of robust security focused packages available through NPM and my prexisting familiarity with them.

Packages such as Crypto, Passport, CSURF, Multer, Helmet, Express-session, CORS, Winston, and Morgan were used throughout development. 
User stories set out in the inital planning phase JIRA board were used as a reference during the development to track progress. 
Some of the development tasks from the planning board were not implemented due to their high complexity and my relatively small time frame.

#Authentication
Passport.js was used to handle user registration & user authentication and login.
Passwords are securely hashed using the Crypto package with the PBKDF2 algorithm and then salted to ensure proper storage of user secrets and to prevent the use of rainbow tables. 
Included in the initial JIRA board was MFA, automated account lockouts, and third party OAuth service login options. 
If this application were to become a production application these would be implemented to improve the application’s security.

#Authorisation
Authorisation is implemented using a custom middleware that calls passport’s built-in function isAuthenticated(), which checks whether or not the incoming request has a valid login. 
When a user first registers a flag is set in the user record to record whether or not this account belongs to an administrator, this allows the same custom middleware to confirm whether or not the request is coming from a person with admin privileges. Currently this admin flag is toggled manually in the code, but this would of course be changed for a more secure solution for a production version of the application. 
With the use of isAuthenticated() & isAdmin() the server can implement role-based access control for certain routes. 
In the case of this project there are two protected routes, the merchant file upload portal, and the admin panel that shows meta-data about all the files uploaded. 
Throughout development of the authN & authZ processes OWASP guidelines such as RBAC, PoLP, proper password validation & handling and several others were implemented to build a secure application.

#Session Management
Sessions are handled using Express-Session, session data is stored on the Mongodb database.
Sessions tokens are configured with security in mind and follow OWASP’s Session Management guidelines, Session ID’s have a length of 192 bits and use a strong CSPRNG, session tokens are regenerated on auth, cookie headers such as “secure”, “SameSite”,“ HTTPOnly“ are used with HSTS configured, session cookies have a maxAge of 24 hours, a new session ID is generated for each new visit to the site, and session tokens are destroyed on logout.

#CSRF
CSRF tokens are used on the merchant file-upload page to verify incoming requests as being from the authenticated user. 
The package CSURF is used to generate and validate tokens from the user’s session, when the form is submitted the server checks if the CSRF token matches. 
In this case tokens had to be sent to the server using a URL parameter due to the way the package Multer (used for form submission/validation) handles multi-part forms. 
In a production version of this application proper implementation with CSRF tokens embedded as a hidden input inside the form would be preferred as the current implementation does risk exposing tokens to bad actors through logs and browser history.
OWASP’s CSRF prevention cheat sheet was used in the implementation of CSRF tokens.

#Data Validation & Sanitisation
Multer is used to handle form submission to ensure proper validation of the file-upload form, more specifically, to restrict file type and size.
Multer also handles processing the file upload. 
General text based input validation is done with express-validator on inputs such as usernames and passwords to ensure they meet minimum complexity requirements and follow OWASP guidelines on Authentication.
Usernames must at minimum be 3 characters long and passwords must be between 8 and 30 characters long, contain at least 1 uppercase letter, 1 lowercase letter, and 1 number. 
Merchant files are restricted to only be .PDFs and less than 1MB in size. 
For input sanitization packages XSS & express-mongo-sanitise are used to automatically escape & encode any potentially malicious inputs before being stored on the database or shown on the page. Fortunately, in the case of this basic application only usernames and filenames are user-controlled data. 
OWASP’s cheat sheets on XSS & SQL Injection prevention were used in the implementation of input sanitisation. An ODM is also used to further mitigate the chance of a successful SQL injection attack.

#Data Handling & Storage 
The ODM Mongoose is used to implement schemas for another layer of protection against SQL injection attacks as it allows for the abstraction of user input in database queries. 
When a user first submits a file it is stored in the file system as temporary storage with a new name given to it by the server. 
As incorporating a full virus scan API is out of scope for this simple implementation a simulated version is
used instead to randomly decide if a file is marked as safe or unsafe. 
In a real-world scenario this RNG function would be replaced with sending the file to a third-party API to perform a virus scan, and a CAPTCHA system would be implemented to prevent automated scripts.
If the file is found to be safe then it is encrypted at rest to AES256 bit level using the Crypto package, and is then stored in the MongoDB as an encrypted binary. If a file is marked as unsafe it is removed from local storage and an event log is made. Regardless of outcome the temporary files are removed from the local file system once the operation is complete. 
OWASP’s file handling cheat sheet was used as a guide to securely implement file-submission handling & storage.
User auth data, session data, files, and logs are stored securely with Mongoose schemas. 
The tables used in the db require authentication. 
User accounts were created with simple read and write permissions so as to follow the principle of least privilege. 
Mongodb has been configured to block all requests originating from outside IP’s and to log all activity. 
In a production application Mongodb enterprise edition would be used to enable disk level encryption at rest and TLS encryption in transit. 
Field level encryption would also be performed on all sensitive user data rather than just the merchant files as has been done in this example. 
Finally, database backups would be scheduled to occur on a regular basis. 

#Logging & Error Handling
Package’s Winston and Morgan are used for logging. 
Morgan logs all incoming HTTP requests to the console so they can be viewed live. 
Winston logs are created when an operation occurs that requires a record of an incident, examples include: uploaded file failing the virus scan, if someone fails a login, if there is a server error, or if an unauthenticated user tries to navigate to a protected route will trigger a log event to occur. 
Information such as the URL, status, user agent, and originating IP address are recorded with a reason for the record. 
Logs are stored securely on the MongoDB database. 
Whenever an error occurs, the event is caught and a basic error message is returned to the user whilst a more detailed log of the event is triggered.

#Secure Configuration
All secrets are stored in and called from environment variables to prevent exposure of sensitive information. 
If this project were running on a public domain rather than localhost the communication between the client and the server would be encrypted using HSTS. 
As stated, this project makes use of RBAC, CSRF Protection, and Data Sanitisation. 
It also makes use of rate limiting, secure session cookies, secure headers, CSP, CORS, feature policies, and other security configuration measures. 
If this were a production application a CDN with DDOS protection would be implemented as well as firewall protection.
