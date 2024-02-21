from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.select import Select
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import time
driver = webdriver.Chrome()
# driver.implicitly_wait(30)
driver.get("https://opensource-demo.orangehrmlive.com/web/index.php/auth/login")
mywait = WebDriverWait(driver,220)
element = mywait.until(EC.presence_of_element_located((By.NAME,"username")))
element.send_keys("Admin")
element = driver.find_element(By.NAME,"password")
element.send_keys("admin123")
driver.find_element(By.XPATH,"//button[@type='submit']").click()
print(driver.title)

time.sleep(10)


# import pdb; pdb.set_trace()