
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
driver.maximize_window()


driver.get("https://demo.automationtesting.in/Alerts.html")
driver.find_element(By.LINK_TEXT,"Alert with OK").click()
driver.find_element(By.ID,"OKTab").click()
driver.switch_to.alert.accept()
time.sleep(3)
driver.find_element(By.XPATH,"//a[@href='#CancelTab']").click()
time.sleep(3)
driver.find_element(By.ID,"CancelTab").click()

time.sleep(2)
driver.switch_to.alert.dismiss()

driver.find_element(By.XPATH,"//a[@href='#Textbox']").click()

driver.find_element(By.ID,"Textbox").click()
time.sleep(3)

time.sleep(4)
tx = driver.switch_to.alert.text
print(tx)

driver.switch_to.alert.send_keys("krisna")
driver.switch_to.alert.accept()

time.sleep(3)