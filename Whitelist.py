import cv2
import numpy as np
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import face_recognition

# Load known face encodings and names
arya_image = face_recognition.load_image_file(r"G:\SDC\FOCUS-main\FOCUS-main\accepted faces\ayra.jpg")
arya_face_encoding = face_recognition.face_encodings(arya_image)[0]

known_face_encodings = [arya_face_encoding]
known_face_names = ["Arya Mirani"]

# Initialize the video capture
video_capture = cv2.VideoCapture(0)

while True:
    ret, frame = video_capture.read()

    # Find face locations and encodings in the current frame
    face_locations = face_recognition.face_locations(frame)
    face_encodings = face_recognition.face_encodings(frame, face_locations)
    face_names = []

    for face_encoding in face_encodings:
        matches = face_recognition.compare_faces(known_face_encodings, face_encoding)
        name = "Unknown"

        if any(matches):
            name = known_face_names[matches.index(True)]

        face_names.append(name)

    for (top, right, bottom, left), name in zip(face_locations, face_names):
        top *= 4
        right *= 4
        bottom *= 4
        left *= 4

        cv2.rectangle(frame, (left, top), (right, bottom), (0, 0, 255), 2)
        cv2.rectangle(frame, (left, bottom - 35), (right, bottom), (0, 0, 255), cv2.FILLED)
        font = cv2.FONT_HERSHEY_DUPLEX
        cv2.putText(frame, name, (left + 6, bottom - 6), font, 1.0, (255, 255, 255), 1)

        if name != "Unknown":
            os.startfile(r"G:\SDC\FOCUS-main\FOCUS-main\Whitelisted Ports.txt")

        cv2.imshow('Video', frame)



# Release the video capture and close all windows
        video_capture.release()
        cv2.destroyAllWindows()

        if name == "Unknown":
            cap = cv2.VideoCapture(0)
            ret, frame = cap.read()
            cap.release()
            cv2.imwrite("G:\SDC\FOCUS-main\FOCUS-main\illegal logins\photo2.jpg", frame)

    # SENDING AN EMAIL FOR UNAUTHORIZED ACCESS
            smtp_port = 587                 
            smtp_server = "smtp.gmail.com"  

            email_from = "aryamirani06@gmail.com"
            email_list = ["aryaamiranii@gmail.com", "28278.arya@iswkoman.com"]
            pswd = "xbxskelbiclhyjcz" 
            subject = "UNAUTHORIZED LOGIN ATTEMPT !!"

        def send_emails(email_list):
            for person in email_list:
                body = f"""
                THIS PERSON TRIED TO ACCESS THE WHITELIST WITHOUT AUTHORIZATION """
                msg = MIMEMultipart()
                msg['From'] = email_from
                msg['To'] = person
                msg['Subject'] = subject

                msg.attach(MIMEText(body, 'plain'))

                filename = "G:\SDC\FOCUS-main\FOCUS-main\illegal logins\photo2.jpg"
                attachment = open(filename, 'rb')  # r for read and b for binary
                attachment_package = MIMEBase('application', 'octet-stream')
                attachment_package.set_payload((attachment).read())
                encoders.encode_base64(attachment_package)
                attachment_package.add_header('Content-Disposition', "attachment; filename= " + filename)
                msg.attach(attachment_package)

                text = msg.as_string()
                TIE_server = smtplib.SMTP(smtp_server, smtp_port)
                TIE_server.starttls()
                TIE_server.login(email_from, pswd)

                print()
                TIE_server.sendmail(email_from, person, text)
                print()

            TIE_server.quit()

        send_emails(email_list)
        quit()
