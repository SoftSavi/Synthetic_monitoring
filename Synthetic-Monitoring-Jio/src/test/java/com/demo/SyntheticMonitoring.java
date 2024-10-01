package com.demo;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.openqa.selenium.*;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.quartz.*;
import org.quartz.impl.StdSchedulerFactory;
import java.time.Duration;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class SyntheticMonitoring {

    public static WebDriver driver;
    private static Logger logger = Logger.getLogger("ResponseLog");
    private static final String SECRET_KEY = "pm#dds$rxz4jhsdt"; // AES-128 key (16 characters)
    private static String selectedBrowser = null;

    public static void main(String[] args) throws InterruptedException {
        try {
            System.out.println("Job scheduled to run every 5 minutes.");

            // Set up Quartz Job and Trigger for URL monitoring every 5 minutes
            JobDetail job = JobBuilder.newJob(UrlMonitoringJob.class)
                    .withIdentity("urlMonitoringJob", "group1")
                    .build();

            Trigger trigger = TriggerBuilder.newTrigger()
                    .withIdentity("urlTrigger", "group1")
                    .withSchedule(SimpleScheduleBuilder.simpleSchedule()
                            .withIntervalInMinutes(5)
                            .repeatForever())
                    .build();

            // Create and start the scheduler
            Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();
            scheduler.start();

            // Schedule the job
            scheduler.scheduleJob(job, trigger);

        } catch (SchedulerException e) {
            e.printStackTrace();
        }
    }

    public void monitorUrls() throws InterruptedException, IOException {
        setupLogger();

        if (selectedBrowser == null) {
            System.out.println("What is your browser?");
            Scanner scanner = new Scanner(System.in);
            selectedBrowser = scanner.nextLine();
            scanner.close();
            System.out.println(selectedBrowser + " browser selected!");
        } else {
            System.out.println("Using previously selected browser: " + selectedBrowser);
        }

        initializeDriver(selectedBrowser);

        ObjectMapper objectMapper = new ObjectMapper();
        List<Map<String, Object>> urlDataList;

        try {
            urlDataList = objectMapper.readValue(new File("E:\\MultiSynthetic\\synthetic.json"),
                    new TypeReference<List<Map<String, Object>>>() {
                    });
        } catch (Exception e) {
            e.printStackTrace();
            return; // Exit if file read fails
        }

        // Sequentially process each URL entry
        for (Map<String, Object> entry : urlDataList) {
            processEntry(entry);
        }

        driver.quit();
    }

    private static void initializeDriver(String browser) {
        if (browser.equalsIgnoreCase("chrome")) {
            System.setProperty("webdriver.chrome.driver",
                    "E:\\AutomationTesting Projects\\Synthetic-Monitoring-Jio\\chromedriver.exe");
            driver = new ChromeDriver();
        } else if (browser.equalsIgnoreCase("edge")) {
            System.setProperty("webdriver.edge.driver",
                    "D:\\UpdatedBasicAutomation\\JavaEmailSenderNew\\msedgedriver.exe");
            driver = new EdgeDriver();
        } else if (browser.equalsIgnoreCase("firefox")) {
            System.setProperty("webdriver.gecko.driver",
                    "D:\\UpdatedBasicAutomation\\JavaEmailSenderNew\\geckodriver.exe");
            driver = new FirefoxDriver();
        } else {
            System.out.println("Unsupported browser! Defaulting to Chrome.");
            System.setProperty("webdriver.chrome.driver",
                    "E:\\AutomationTesting Projects\\Synthetic-Monitoring-Jio\\chromedriver.exe");
            driver = new ChromeDriver();
        }
    }

    private static void processEntry(Map<String, Object> entry) throws InterruptedException {
        String baseUrl = (String) entry.get("url");
        int expectedResponseTime = (int) entry.get("expectedResponseTime");
        int expectedResponseCode = (int) entry.get("expectedResponseCode");
        @SuppressWarnings("unchecked")
        List<String> expectedResponse = (List<String>) entry.get("expectedResponse");

        RestAssured.baseURI = baseUrl;
        driver.get(RestAssured.baseURI);
        driver.manage().timeouts().implicitlyWait(10, TimeUnit.SECONDS);
        driver.manage().window().maximize();

        boolean requiresCredentials = entry.containsKey("requiresCredentials") && (boolean) entry.get("requiresCredentials");

        if (requiresCredentials) {
            loadAndUseCredentials(entry); // Handle credentials
        }

        // Allow page to load completely
        Thread.sleep(5000);

        String currentUrl = driver.getCurrentUrl();
        long responseTime = getResponseTime(currentUrl);
        int responseCode = getResponseCode(currentUrl);
        StringBuilder emailBody = new StringBuilder();

        logger.info("URL: " + currentUrl);

        // Check response time
        if (responseTime > expectedResponseTime) {
            logger.warning("Response time exceeded the expected range.");
            emailBody.append("The response time exceeded the expected time.\n");
        } else {
            logger.info("Response time is within the expected range.");
        }

        // Check response code
        logger.info("Response Code: " + responseCode);
        if (responseCode == expectedResponseCode) {
            logger.info("Response code matches the expected code.");
        } else {
            logger.warning("Response code does not match the expected code.");
            emailBody.append("The response code did not match the expected code.\n" +
                    "Expected Response Code: " + expectedResponseCode + "\n" +
                    "Actual Response Code: " + responseCode + "\n");
        }

        // Check expected content
        String pageSource = driver.getPageSource();
        boolean isMatchFound = false;
        for (String expectedName : expectedResponse) {
            if (pageSource.contains(expectedName)) {
                logger.info("Match found in HTML: " + expectedName);
                isMatchFound = true;
                break;
            }
        }

        if (!isMatchFound) {
            logger.warning("Expected result does not match: No names are present in the page's HTML content.");
            emailBody.append("None of the expected content was found on the page.\n");
        } else {
            logger.info("Expected result matches: At least one name is present in the page's HTML content.");
        }

        // Send email if alerts are raised
        if (emailBody.length() > 0) {
            emailBody.insert(0, "Alerts for the URL: " + currentUrl + "\n\n");
            sendEmail("Alert Notification", emailBody.toString());
        }

        logger.info("===========================");
    }


    private static long getResponseTime(String currentUrl) {
        long startTime = System.currentTimeMillis();
        RestAssured.given().get(currentUrl);
        return System.currentTimeMillis() - startTime;
    }

    private static int getResponseCode(String currentUrl) {
        Response res = RestAssured.given().get(currentUrl);
        return res.getStatusCode();
    }

    private static void loadAndUseCredentials(Map<String, Object> entry) {
        try {
            String loginType = (String) entry.getOrDefault("loginType", "singleStep");
            if (!entry.containsKey("credentials")) {
                logger.severe("No credentials provided for a URL that requires login.");
                return;
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> credentials = (Map<String, Object>) entry.get("credentials");
            String encryptedUsername = (String) credentials.get("encrypted.username");
            String encryptedPassword = (String) credentials.get("encrypted.password");

            String decryptedUsername = decrypt(encryptedUsername, SECRET_KEY);
            String decryptedPassword = decrypt(encryptedPassword, SECRET_KEY);

            switch (loginType.toLowerCase()) {
                case "singlestep":
                    inputCredentials(credentials, decryptedUsername, decryptedPassword);
                    break;
                case "multistep":
                    inputNextButtonCredentials(credentials, decryptedUsername, decryptedPassword);
                    break;
                case "threestep": // New case for three-step login
                    threeStepLogin(credentials, decryptedUsername, decryptedPassword);
                    break;    
                default:
                    logger.warning("Unknown login type, defaulting to single-step.");
                    inputCredentials(credentials, decryptedUsername, decryptedPassword);
            }
        } catch (Exception e) {
            logger.severe("Error loading credentials: " + e.getMessage());
        }
    }

    private static void inputCredentials(Map<String, Object> credentialLocators, String username, String password) {
        try {
            WebElement usernameField = driver.findElement(getLocator(credentialLocators, "usernameLocator"));
            usernameField.sendKeys(username);
            logger.info("Username entered: " + username);

            WebElement passwordField = driver.findElement(getLocator(credentialLocators, "passwordLocator"));
            passwordField.sendKeys(password);
            logger.info("Password entered: " + password);

            WebElement loginButton = driver.findElement(getLocator(credentialLocators, "submitLocator"));
            loginButton.click();
            logger.info("Login button clicked.");

        } catch (NoSuchElementException e) {
            logger.severe("Element not found during login: " + e.getMessage());
        }
    }

    private static void inputNextButtonCredentials(Map<String, Object> credentialLocators, String username, String password) {
        try {
            WebElement usernameField = driver.findElement(getLocator(credentialLocators, "usernameLocator"));
            usernameField.sendKeys(username);
            logger.info("Username entered: " + username);

            WebElement nextButton = driver.findElement(getLocator(credentialLocators, "nextLocator"));
            nextButton.click();
            logger.info("Next button clicked.");

            Thread.sleep(2000); // Wait for the password field

            WebElement passwordField = driver.findElement(getLocator(credentialLocators, "passwordLocator"));
            passwordField.sendKeys(password);
            logger.info("Password entered: " + password);

            WebElement loginButton = driver.findElement(getLocator(credentialLocators, "submitLocator"));
            loginButton.click();
            logger.info("Submit button clicked.");

        } catch (NoSuchElementException | InterruptedException e) {
            logger.severe("Element not found during multi-step login: " + e.getMessage());
        }
    }
    
    private static void threeStepLogin(Map<String, Object> credentialLocators, String username, String password) {
        try {
            // Click the initial "Click here to login" button
            WebElement clickHereButton = driver.findElement(getLocator(credentialLocators, "clickHereLocator"));
            clickHereButton.click();
            logger.info("Click here button clicked.");
 
            // Wait for the username field to become visible
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10)); // Use Duration for the timeout
            wait.until(ExpectedConditions.visibilityOfElementLocated(getLocator(credentialLocators, "usernameLocator")));
           
            // Enter the username
            WebElement usernameField = driver.findElement(getLocator(credentialLocators, "usernameLocator"));
            usernameField.sendKeys(username);
            logger.info("Username entered: " + username);

            // Enter the password
            WebElement passwordField = driver.findElement(getLocator(credentialLocators, "passwordLocator"));
            passwordField.sendKeys(password);
            logger.info("Password entered: " + password);

            // Click the login button
            WebElement loginButton = driver.findElement(getLocator(credentialLocators, "submitLocator"));
            loginButton.click();
            logger.info("Login button clicked.");

        } catch (NoSuchElementException e) {
            logger.severe("Element not found during three-step login: " + e.getMessage());
        }
    }
    
    
    @SuppressWarnings("unchecked")
	private static By getLocator(Map<String, Object> credentialLocators, String locatorType) {
        Map<String, String> locatorDetails = (Map<String, String>) credentialLocators.get(locatorType);
        String locatorValue = locatorDetails.get("value");
        String locatorMethod = locatorDetails.get("type");

        switch (locatorMethod) {
            case "xpath":
                return By.xpath(locatorValue);
            case "id":
                return By.id(locatorValue);
            case "css":
                return By.cssSelector(locatorValue);
            default:
                throw new IllegalArgumentException("Invalid locator method: " + locatorMethod);
        }
    }


    private static String decrypt(String encryptedData, String secretKey) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedBytes);
        } catch (Exception e) {
            logger.severe("Error decrypting data: " + e.getMessage());
            return null;
        }
    }

    private static void sendEmail(String subject, String body) {
		try {
			// Load email credentials from properties file
			Properties emailProps = new Properties();
			try (FileInputStream input = new FileInputStream("src/test/resources/credentials.properties")) {
				emailProps.load(input);
			}

			// Plain text email ID
			String username = emailProps.getProperty("email.username");

			// Encrypted email password
			String encryptedPassword = emailProps.getProperty("encrypted.email.password");
			String smtpHost = emailProps.getProperty("smtp.host");
			String adminEmail = emailProps.getProperty("admin.email");

			if (username == null || encryptedPassword == null || smtpHost == null || adminEmail == null) {
				logger.severe("One or more email credentials are missing or null. Please check the properties file.");
				return;
			}

			// Decrypt email password
			String password = decrypt(encryptedPassword, SECRET_KEY);

			// Set up email properties
			Properties props = new Properties();
			props.put("mail.smtp.auth", "true");
			props.put("mail.smtp.starttls.enable", "true");
			props.put("mail.smtp.host", smtpHost);
			props.put("mail.smtp.port", "587");

			Session session = Session.getInstance(props, new Authenticator() {
				protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(username, password); // Use decrypted password here
				}
			});

			Message message = new MimeMessage(session);
			message.setFrom(new InternetAddress(username));
			message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(adminEmail));
			message.setSubject(subject);
			message.setText(body);

			Transport.send(message);
			logger.info("Email sent successfully to " + adminEmail);
		} catch (Exception e) {
			logger.severe("Failed to send email: " + e.getMessage());
		}
	}


    private static void setupLogger() throws IOException {
		FileHandler fileHandler = new FileHandler("E:\\MultiSynthetic\\syntheticlog.log", false);
		logger.addHandler(fileHandler);
		SimpleFormatter formatter = new SimpleFormatter();
		fileHandler.setFormatter(formatter);
		logger.setUseParentHandlers(false);
	}
    public static class UrlMonitoringJob implements Job {
        @Override
        public void execute(JobExecutionContext context) throws JobExecutionException {
            SyntheticMonitoring syntheticMonitoring = new SyntheticMonitoring();
            try {
                syntheticMonitoring.monitorUrls();
            } catch (InterruptedException | IOException e) {
                logger.severe("Job execution failed: " + e.getMessage());
            }
        }
    }
}
