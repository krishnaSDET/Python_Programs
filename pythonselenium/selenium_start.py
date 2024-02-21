import pdb

from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.select import Select
import time

chr_options = Options()
chr_options.add_experimental_option("detach",True)
# driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chr_options)
driver = webdriver.Chrome()
driver.get("http://demo.automationtesting.in")
text = driver.find_element(By.ID,"email")
text.send_keys("test@ymail.com")
driver.find_element(By.ID,"enterimg").click()
name = driver.find_element(By.XPATH,"//input[@placeholder='First Name']")
name.send_keys("krishna")
name = driver.find_element(By.CSS_SELECTOR,"input[placeholder='Last Name']")
name.send_keys("ram")
driver.implicitly_wait(10)
name = driver.find_element(By.XPATH,"//form[@id='basicBootstrapForm']/child::div/div/textarea[@ng-model='Adress']")
# pdb.set_trace()
name.send_keys("pondy")
driver.find_element(By.XPATH,'//input[@value="Male"]').click()
driver.find_element(By.XPATH,'//input[@value="Cricket"]').click()
driver.implicitly_wait(30)

li = driver.find_elements(By.XPATH,"//input[@type='checkbox']")
for val in li:
    value = val.get_attribute("value")
    print(value)
    if value =="Movies":
        val.click()


elm = driver.find_element(By.ID,"Skills")
sel = Select(elm)
sel.select_by_index(2)
time.sleep(3)
sel.select_by_value("APIs")
sel.select_by_visible_text("C")
time.sleep(4)
# assert "Python" in driver.title
# elem = driver.find_element(By.NAME, "q")
# elem.clear()
# elem.send_keys("pycon")
# elem.send_keys(Keys.RETURN)
# assert "No results found." not in driver.page_source
# driver.close()