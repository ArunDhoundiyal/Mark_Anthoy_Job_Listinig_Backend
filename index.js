const express = require('express');
const {checkUserCredentials, checkLoginCredentials} = require('./check-user-credentials');
const {v4:uuidv4} = require('uuid')
const jwt = require('jsonwebtoken');
const bcrypt = require("bcrypt");
const cors = require('cors');
const sqlite3 = require('sqlite3');
const {open} = require('sqlite');
const path = require('path');
const dbPath = path.join(__dirname, 'job.db');
let dataBase = null;
const serverInstance = express();
serverInstance.use(express.json());
serverInstance.use(express.urlencoded({ extended: true }));
serverInstance.use(cors());
const Port = process.env.PORT || 4000;

const initializeDatabaseSever = async() => {
    try {
        dataBase = await open({
            filename:dbPath,
            driver:sqlite3.Database
        })
        serverInstance.listen(Port, ()=>{
            console.log(`Server is running on the PORT:- http://localhost:${Port}`)
        })
        console.log('Database initialized:', dataBase)

        
    } catch (error) {
        console.log(`Database Error: ${error}`)
        process.exit(1);
    }
};
initializeDatabaseSever();

// Token Authorization (Middleware Function)
const authenticateToken  = (request, response, next) => {
    let jwtToken;
    const authHeader = request.headers['authorization'];
    if (!authHeader) return response.status(401).json({error:"Authorization header missing..!"});
    jwtToken = authHeader.split(' ')[1];
    if (!jwtToken) return response.status(401).json({error:"Unauthorized Access Token..!"});
    jwt.verify(jwtToken, "MY_SECRET_TOKEN", async(error, payload)=>{
        if (error) return response.status(403).json({error:"Invalid Token"});
        request.email = payload.email
        next()
    })
};

// user registration 
serverInstance.post('/signup', async (request, response) => {
    try {
        const { userName, userEmail, userPassword, userPhoneNumber } = request.body;

        if (!userName || !userEmail || !userPassword || !userPhoneNumber) {
            return response.status(400).json({ error: 'All user details are mandatory..!' });
        }
        const { error } = checkUserCredentials.validate({
            user_name: userName,
            user_email: userEmail,
            user_password: userPassword,
            contact_phonenumber:userPhoneNumber
        });
        if (error) {
            return response.status(400).json({ error: error.details[0].message });
        }
        const checkUserExist = await dataBase.get('SELECT * FROM user WHERE email = ?', [userEmail]);
        if (checkUserExist) {
            return response.status(400).json({ error: `User ${checkUserExist.email} already exists..!` });
        }
        const hashedPassword = await bcrypt.hash(userPassword, 10);
        await dataBase.run(
            'INSERT INTO user(id, name, email, password, phone_number) VALUES (?, ?, ?, ?, ?)', 
            [uuidv4(), userName, userEmail, hashedPassword, userPhoneNumber]
        );

        return response.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        return response.status(500).json({ error: error.message });
    }
});

// user login 
serverInstance.post('/login', async(request, response)=>{
    const {userEmail, userPassword} = request.body;
    try {
        if (!userEmail || !userPassword){
            return response.status(400).json({error:'Valid user email and password both are mandatory..!'})
        }
    
        const {error} = checkLoginCredentials.validate({
            user_email:userEmail,
            user_password: userPassword
        })
        if (error){
            return response.status(400).json({ error: error.details[0].message });
        }
        const checkLoginUser = await dataBase.get('SELECT * FROM user WHERE email = ?', [userEmail]);
        if (!checkLoginUser){
            return response.status(400).json({error:'Invalid user login email..!'});
        } 

        const checkPassword = await bcrypt.compare(userPassword, checkLoginUser.password);
        if (checkPassword){
            const payload = {email: checkLoginUser.email};
            const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN');
            response.status(200).json({jwt_token:jwtToken})
            console.log({jwt_token:jwtToken})
        }
        else{
            response.status(400).json({error:"Invalid user login password..!"})
        }
    
        
    } catch (error) {
        response.status(500).json({error:`Error while login: ${error.message}`})
    }

});

// User profile 
serverInstance.get('/profile', authenticateToken, async(request, response)=>{
    const {email} = request;
    try {
        const getUser = await dataBase.get('SELECT * FROM user WHERE email = ?', [email]);
        if (!getUser) return response.status(401).json({error_message:'User not found. Kindly register or login first..!'})
        response.status(200).json({user_profile:getUser});
        
    } catch (error) {
        response.status(500).json({error_message:error.message});
    }

});

// Create Job Post
serverInstance.post('/job', authenticateToken, async(request, response)=>{
    const {email} = request;
    const {
        numberOfPosition,
        companyName, 
        companyLogo, 
        jobPosition, 
        monthlySalary, 
        jobType, 
        remoteOrOffline, 
        location, 
        jobDescription,
        aboutCompany, 
        skills, 
        additionalInformation
    } = request.body;
    try {
        if (!numberOfPosition || !companyName || !companyLogo || !jobPosition || !monthlySalary || !jobType || !remoteOrOffline || !location || !jobDescription || !aboutCompany || !skills || !additionalInformation) return response.status(400).json({error_message:'All job details are mandatory to give for creating..!'})
        const getUser = await dataBase.get('SELECT * FROM user WHERE email = ?', [email]);
        if (!getUser) return response.status(401).json({error_message:'User not found. Kindly register or login first..!'})
            await dataBase.run(
                `INSERT INTO job (user_id, number_of_position, company_name, company_logo, job_position, monthly_salary, job_type, remote_or_inoffice, location, job_description, about_company, skills, additional_information) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [getUser.id, numberOfPosition, companyName, companyLogo, jobPosition, monthlySalary, jobType, remoteOrOffline, location, jobDescription, aboutCompany, skills, additionalInformation]
            );
        response.status(201).json({message:`Job Created successfully by the ${getUser.email}`})
    } catch (error) {
        response.status(500).json({error_message:error.message});
    }
});


// Update job 
serverInstance.put('/job/:id', authenticateToken, async(request, response)=>{
    const {email} = request;
    const {id} = request.params;
    try {
        const getJobDetail = await dataBase.get('SELECT * FROM job WHERE id = ? AND user_id = (SELECT id FROM user WHERE email = ?)', [id, email]);
        const getBookmarkJobDetail = await dataBase.get('SELECT * FROM bookmark WHERE id = ? AND user_id = (SELECT id FROM user WHERE email = ?)', [id, email]);
        
        const {
            numberOfPosition = getJobDetail.number_of_position,
            companyName=getJobDetail.company_name, 
            companyLogo=getJobDetail.company_logo, 
            jobPosition=getJobDetail.job_position, 
            monthlySalary=getJobDetail.monthly_salary, 
            jobType=getJobDetail.job_type, 
            remoteOrOffline=getJobDetail.remote_or_inoffice, 
            location=getJobDetail.location, 
            jobDescription=getJobDetail.job_description,

            aboutCompany=getJobDetail.about_company, 
            skills=getJobDetail.skills, 
            additionalInformation=getJobDetail.additional_information
        } = request.body;
        await dataBase.run('UPDATE job SET number_of_position = ?, company_name = ?, company_logo = ?, job_position = ?, monthly_salary = ?, job_type = ?, remote_or_inoffice = ?, location = ?, job_description = ?, about_company = ?, skills = ?, additional_information = ? WHERE id = ? AND user_id = (SELECT id FROM user WHERE email = ?)',
            [numberOfPosition, companyName, companyLogo, jobPosition, monthlySalary, jobType, remoteOrOffline, location, jobDescription, aboutCompany, skills, additionalInformation, id, email]
        );
        if (getBookmarkJobDetail){
            await dataBase.run('UPDATE bookmark SET number_of_position = ?, company_name = ?, company_logo = ?, job_position = ?, monthly_salary = ?, job_type = ?, remote_or_inoffice = ?, location = ?, job_description = ?, about_company = ?, skills = ?, additional_information = ? WHERE id = ? AND user_id = (SELECT id FROM user WHERE email = ?)',
                [numberOfPosition, companyName, companyLogo, jobPosition, monthlySalary, jobType, remoteOrOffline, location, jobDescription, aboutCompany, skills, additionalInformation, id, email]);
        }
        response.status(200).json({message:'Job updated successfully..!'})
        
    } catch (error) {
        response.status(500).json({error_message:error.message});
    }
});


// Delete job
serverInstance.delete('/job/:id', authenticateToken, async(request, response)=>{
    const {email} = request;
    const {id} = request.params;
    try {
        const deleteJob = await dataBase.run(`DELETE FROM job WHERE id = ? AND user_id = (SELECT id FROM user WHERE email = ?)`, [id, email]); 
        if (deleteJob.changes === 0){
            return response.status(404).json({ message: "Job not found or unauthorized access" });
        }
        response.json({ message: `Job deleted successfully`});
        
    } catch (error) {
        response.status(500).json({ error_message: error.message });
    }
});

// Read a Single Job Listing
serverInstance.get('/job/:id', async (request, response) => {
    const { id } = request.params;
    try {
        const getJob = await dataBase.get('SELECT * FROM job WHERE id = ?', [id]);
        if (!getJob) {
            return response.status(404).json({ message: "Job data not found in the database." });
        }
        response.status(200).json({ job_data: getJob });
    } catch (error) {
        response.status(500).json({ error_message: error.message });
    }
});

//Create Bookmark Jobs
serverInstance.post('/bookmark/:id', authenticateToken, async (request, response)=>{
    const {id}=request.params;
    const {email} = request; 
    try {
        const getLoginUser = await dataBase.get('SELECT * FROM user WHERE email = ?',[email]);
        if (!getLoginUser) return response.status(404).json({ message: "User not found..!" });
        const getJobData = await dataBase.get('SELECT * FROM job WHERE id = ?', [id]);
        console.log(getJobData)
        if (!getJobData) return response.status(404).json({message:'Job data not found in the database for bookmark..!'});
        await dataBase.run(`INSERT INTO bookmark (id, number_of_position, user_id, login_user_id, company_name, company_logo, job_position, monthly_salary, job_type, remote_or_inoffice, location, job_description, about_company, skills, additional_information) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, 
            [getJobData.id, getJobData.numberOfPosition, getJobData.user_id, getLoginUser.id, getJobData.company_name, getJobData.company_logo, getJobData.job_position, getJobData.monthly_salary, getJobData.job_type, getJobData.remote_or_inoffice, getJobData.location, getJobData.job_description, getJobData.about_company, getJobData.skills, getJobData.additional_information]
        );
        response.status(201).json({message:'Bookmark Job data create and store successfully..!'});
    } catch (error) {
        response.status(500).json({error_message:error.message})
        
    }
});


// Get all Bookmark
serverInstance.get('/bookmark', authenticateToken, async(request, response)=>{
    const {email} = request;
    try {
        const getLoginUser = await dataBase.get('SELECT * FROM user WHERE email = ?',[email]);
        if (!getLoginUser) {
            return response.status(404).json({ message: "User not found..!" });
        }
        const getAllBookmark = await dataBase.all('SELECT * FROM bookmark WHERE login_user_id = ?', [getLoginUser.id]);
        response.status(200).json({bookmark_data:getAllBookmark});
        
    } catch (error) {
        response.status(500).json({error_message:error.message});
    }
});

// Get Bookmark 
serverInstance.get('/bookmark/:id', authenticateToken, async (request, response)=>{
    const {id}=request.params;
    const {email} = request;
    try {
        const getLoginUser = await dataBase.get('SELECT * FROM user WHERE email = ?',[email]);
        if (!getLoginUser) return response.status(404).json({ message: "User not found..!" });
        const getBookmark = await dataBase.get('SELECT * FROM bookmark WHERE id = ? AND login_user_id = ?', [id, getLoginUser.id]);
        response.status(200).json({bookmark_data:getBookmark});
        
    } catch (error) {
        response.status(500).json({error_message:error.message});
    }

});

// Get Jobs 
serverInstance.get('/job', async(request, response)=>{
    const {jobPosition, companyName, date, salaryRange, location, jobType, skills, pageNo} = request.query;
    try {
        const limit = 5;
        const offset = limit * (Number(pageNo)>0?Number(pageNo)-1:0);
        const condition = [];
        const parameter = []; 
        let query = `SELECT * FROM job`;
        if (jobPosition){
            condition.push(`job_position LIKE ?`);
            parameter.push(`%${jobPosition}%`);
        }
        if (companyName){
            condition.push(`company_name LIKE ?`);
            parameter.push(`%${companyName}%`);
        }
        if (date){
            condition.push('created_at LIKE ?');
            parameter.push(date);
        }
        if (salaryRange){
            condition.push('monthly_salary LIKE ?');
            parameter.push(salaryRange);        
        }
        if (location){
            condition.push('location LIKE ?');
            parameter.push(`%${location}%`);
        }
        if (jobType){
            condition.push('job_type LIKE ?');
            parameter.push(jobType);
        }
        if (skills){
            condition.push('skills LIKE ?');
            parameter.push(`%${skills}%`);
        }
        if (condition.length > 0){
            query+=` WHERE `+ condition.join(' AND ') + ` LIMIT ${limit} OFFSET ${offset}`;
        }
        else{
            query+=` LIMIT ${limit} OFFSET ${offset}`;
        }
        const jobList = await dataBase.all(query, parameter);
        response.status(200).json({job_list:jobList});
        
    } catch (error) {
        response.status(500).json({error_message:error.message});
    }
});




