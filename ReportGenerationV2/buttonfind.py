from comtypes.client import CreateObject
import time

def find_button_using_uia():
    UIA = CreateObject("UIAutomationClient.CUIAutomation")
    element = UIA.ElementFromHandle(hwnd)
    button = element.FindFirst(
        UIA.TreeScope_Descendants,
        UIA.CreatePropertyCondition(
            UIA.UIA_NamePropertyId,
            "Attach screenshots, videos or other documents"
        )
    )
    return button
