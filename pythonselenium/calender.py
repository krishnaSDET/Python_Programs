from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec


driver = webdriver.Chrome()
driver.get("https://jqueryui.com/datepicker/")
driver.maximize_window()
driver.implicitly_wait(10)
driver.switch_to.frame(0)
wait = WebDriverWait(driver,20)
# import time; time.sleep(40)
# import pdb; pdb.set_trace()

wait.until(ec.element_to_be_clickable((By.XPATH,"//input[@id='datepicker']"))).click()
# elem = driver.find_element(By.XPATH,"//input[@id='datepicker']")
# elem.click()
year ='2024'
month = 'June'
date =28
while True:
     curn_month = driver.find_element(By.XPATH,"//span[@class='ui-datepicker-month']").text
     curn_year  = driver.find_element(By.XPATH,"//span[@class='ui-datepicker-year']").text
     if year == curn_year and month ==curn_month:
         break;
     else:
         driver.find_element(By.XPATH, "//a[@title='Next']").click()

dates = driver.find_elements(By.XPATH,"//table[@class='ui-datepicker-calendar']/tbody/tr/td/a")
for val in dates:
    if val.text ==date:
        val.click()
        break
import pdb; pdb.set_trace()