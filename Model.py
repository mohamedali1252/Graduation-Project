import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from keras.utils import np_utils
from keras.models import Sequential
from keras.layers import Dense, Dropout


init_train_df = pd.read_csv('kdd_train.csv')
init_test_df = pd.read_csv('kdd_test.csv')

#Data preprocessing
#Here we aim to remove the issues we found in the dataset in the analysis phase 
#First we will remove the skew in the dataset by downsample the normal and neptune observations (records)

random_state = 42

proc_train_df = init_train_df.copy()
proc_test_df = init_test_df.copy()
# get the slice of our train set with all normal observations
proc_train_normal_slice = proc_train_df[proc_train_df['labels'] == 'normal'].copy()
# get the slice of our train set with all neptune observations
proc_train_neptune_slice = proc_train_df[proc_train_df['labels'] == 'neptune'].copy()
#do the same thing for the test dataset as the skew was found in both datasets
proc_test_normal_slice = proc_test_df[proc_test_df['labels'] == 'normal'].copy()
proc_test_neptune_slice = proc_test_df[proc_test_df['labels'] == 'neptune'].copy()
#Downsample neptune and normal observations to 5000 observation in train dataset
proc_train_normal_sampled = proc_train_normal_slice.sample(n=5000, random_state=random_state)
proc_train_neptune_sampled = proc_train_neptune_slice.sample(n=5000, random_state=random_state)
#Downsample neptune and normal observations to 1000 observation in test dataset
proc_test_normal_sampled = proc_test_normal_slice.sample(n=1000, random_state=random_state)
proc_test_neptune_sampled = proc_test_neptune_slice.sample(n=1000, random_state=random_state)

#Then we will drop the unsampled normal and neptune slices from dataframes in both datasets
proc_train_df.drop(proc_train_df.loc[proc_train_df['labels']=='normal'].index, inplace=True)
proc_train_df.drop(proc_train_df.loc[proc_train_df['labels']=='neptune'].index, inplace=True)
proc_test_df.drop(proc_test_df.loc[proc_test_df['labels']=='normal'].index, inplace=True)
proc_test_df.drop(proc_test_df.loc[proc_test_df['labels']=='neptune'].index, inplace=True)
#lastly we will add the downsampled slices to dataframes of train and test datasets
proc_train_df = pd.concat([proc_train_df, proc_train_normal_sampled, proc_train_neptune_sampled], axis=0)
proc_test_df = pd.concat([proc_test_df, proc_test_normal_sampled, proc_test_neptune_sampled], axis=0)

keep_labels = ['normal', 'neptune', 'satan', 'ipsweep', 'portsweep', 'smurf', 'nmap', 'back', 'teardrop', 'warezclient']

proc_train_df['labels'] = proc_train_df['labels'].apply(lambda x: x if x in keep_labels else 'other')
proc_test_df['labels'] = proc_test_df['labels'].apply(lambda x: x if x in keep_labels else 'other')

seed_random = 718

proc_test_other_slice = proc_test_df[proc_test_df['labels']=='other'].copy()

proc_train_other_sampled, proc_test_other_sampled = train_test_split(proc_test_other_slice, test_size=0.2, random_state=seed_random)

proc_test_df.drop(proc_test_df.loc[proc_test_df['labels']=='other'].index, inplace=True)
print(proc_test_df.shape)

proc_train_df = pd.concat([proc_train_df, proc_train_other_sampled], axis=0)
proc_test_df = pd.concat([proc_test_df, proc_test_other_sampled], axis=0)

norm_cols = [ 'duration', 'src_bytes', 'dst_bytes', 'hot', 'num_compromised', 'num_root', 'num_file_creations', 'count',
             'srv_count', 'dst_host_count', 'dst_host_srv_count']

for col in norm_cols:
    proc_train_df[col] = np.log(proc_train_df[col]+1e-6)
    proc_test_df[col] = np.log(proc_test_df[col]+1e-6)

proc_train_df['train'] = 1
proc_test_df['train'] = 0
joined_df = pd.concat([proc_train_df, proc_test_df])

protocol_dummies = pd.get_dummies(joined_df['protocol_type'], prefix='protocol_type')
service_dummies = pd.get_dummies(joined_df['service'], prefix='service')
flag_dummies = pd.get_dummies(joined_df['flag'], prefix='flag')
joined_df = pd.concat([joined_df, protocol_dummies, service_dummies, flag_dummies], axis=1)
proc_train_df = joined_df[joined_df['train'] == 1]
proc_test_df = joined_df[joined_df['train'] == 0]
drop_cols = ['train', 'protocol_type', 'service', 'flag']
proc_train_df.drop(drop_cols, axis=1, inplace=True)
proc_test_df.drop(drop_cols, axis=1, inplace=True)

y_buffer = proc_train_df['labels'].copy()
x_buffer = proc_train_df.drop(['labels'], axis=1)

y_test = proc_test_df['labels'].copy()
x_test = proc_test_df.drop(['labels'], axis=1)

seed_random = 315

label_encoder = LabelEncoder()
label_encoder = label_encoder.fit(y_buffer)

x_train, x_val, y_train, y_val = train_test_split(x_buffer, y_buffer, test_size=0.3, random_state=seed_random)

input_size = len(x_train.columns)

deep_model = Sequential()
deep_model.add(Dense(256, input_dim=input_size, activation='softplus'))
#deep_model.add(Dropout(0.2))
deep_model.add(Dense(128, activation='relu'))
deep_model.add(Dense(64, activation='relu'))
deep_model.add(Dense(32, activation='relu'))
#deep_model.add(Dense(18, activation='softplus'))
deep_model.add(Dense(11, activation='softmax'))

deep_model.compile(loss='categorical_crossentropy',
                   optimizer='adam',
                   #(learning_rate=0.001, beta_1=0.9, beta_2=0.999, amsgrad=True),
                   metrics=['accuracy'])
y_train_econded = label_encoder.transform(y_train)
y_val_econded = label_encoder.transform(y_val)
y_test_econded = label_encoder.transform(y_test)

y_train_dummy = np_utils.to_categorical(y_train_econded)
y_val_dummy = np_utils.to_categorical(y_val_econded)
y_test_dummy = np_utils.to_categorical(y_test_econded)

deep_model.fit(x_train, y_train_dummy,
               epochs=50,
               batch_size=2500,
               validation_data=(x_val, y_val_dummy))

predtrain = deep_model.predict(x_val)
#predict_x=model.predict(X_test)
deep_val_pred=np.argmax(predtrain,axis=1)
deep_val_pred_decoded = label_encoder.inverse_transform(deep_val_pred)


predtest = deep_model.predict(x_test)
deep_test_pred=np.argmax(predtest,axis=1)
deep_test_pred_decoded = label_encoder.inverse_transform(deep_test_pred)

deep_model.save("my_model.h5")
