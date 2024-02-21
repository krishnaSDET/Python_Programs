from selenium import webdriver
from selenium.webdriver.common.by import  By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec
import time

driver = webdriver.Chrome()
driver.get("https://testautomationpractice.blogspot.com/")
driver.maximize_window()
driver.implicitly_wait(10)
explicit_wait = WebDriverWait(driver,30)
element = explicit_wait.until(ec.presence_of_element_located((By.XPATH,"//table[@name='BookTable']//tr")))
ele = driver.find_elements(By.XPATH,"//table[@name='BookTable']//tr")
rows =len(ele)
columns = len(driver.find_elements(By.XPATH,"//table[@name='BookTable']//tr/th"))
# import pdb; pdb.set_trace()
for ro in range(2,rows+1):
    for co in range(1,columns+1):
        data = driver.find_element(By.XPATH,"//table[@name='BookTable']//tr["+str(ro)+"]/td["+str(co)+"]").text
        print(data, end="     ")
    print( )




# print(len(ele))
time.sleep(3)
driver.close()