#!/usr/bin/python
# -*- coding: utf-8 -*-


import os
import sys
import pickle
import argparse

import numpy
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer

import pefile

PE_Headers = ['Magic', 'MajorLinkerVersion', 'MinorLinkerVersion',
              'SizeOfCode', 'SizeOfInitializedData',
              'SizeOfUninitializedData', 'AddressOfEntryPoint',
              'BaseOfCode', 'BaseOfData', 'ImageBase',
              'SectionAlignment', 'FileAlignment',
              'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
              'MajorImageVersion', 'MinorImageVersion',
              'MajorSubsystemVersion', 'MinorSubsystemVersion',
              'Reserved1', 'SizeOfImage', 'SizeOfHeaders',
              'CheckSum', 'Subsystem', 'DllCharacteristics',
              'SizeOfStackReserve', 'SizeOfStackCommit',
              'SizeOfHeapReserve', 'SizeOfHeapCommit',
              'LoaderFlags', 'NumberOfRvaAndSizes']


def get_peheader_features(path):
    header_features = {}
    
    try:
        if(pefile.PE(path)):
            pe = pefile.PE(path, fast_load=True)
            for header in PE_Headers:
                header_features[header] = eval("pe.OPTIONAL_HEADER."+header)
            header_features['PE_ERROR'] = 0
    except:
        for header in PE_Headers:
            header_features[header] = 0
        header_features['PE_ERROR'] = 1

    vectorizer = DictVectorizer()
    vectorizer.fit([header_features])
    header_features = vectorizer.transform([header_features])
    
    # do some data munging to get the feature array
    header_features = header_features.todense()
    header_features = numpy.asarray(header_features)
    header_features = header_features[0]

    return header_features


def scan_file(path):
    # scan a file to determine if it is malicious or benign
    if not os.path.exists("saved_detector.pkl"):
        print("It appears you haven't trained a detector yet!  Do this before scanning files.")
        sys.exit(1)
    with open("saved_detector.pkl","rb") as saved_detector:
        classifier = pickle.load(saved_detector)
    features = [get_peheader_features(path)]
    
    result_proba = classifier.predict_proba(features)[:, 1]
    # if the user specifies malware_paths and benignware_paths, train a detector
    if result_proba > 0.5:
        print("It appears this file is malicious!",result_proba)
    else:
        print("It appears this file is benign.",result_proba)


def train_detector(benign_path,malicious_path):
    # train the detector on the specified training data
    def get_training_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory,path))
        return targets
    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)
    print("Begin Training...")
    X = [get_peheader_features(path) for path in malicious_paths + benign_paths]
    y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]
    classifier = RandomForestClassifier(64) 
    classifier.fit(X, y)
    print("End Training...")
    print("Begin Saving Models...")
    pickle.dump(classifier, open("saved_detector.pkl", "wb+"))
    print("End Saving Models...")


def cv_evaluate(X,y):
    # use cross-validation to evaluate our model
    import random
    from sklearn import metrics
    from matplotlib import pyplot
    from sklearn.model_selection import KFold
    
    X, y = numpy.array(X), numpy.array(y)
    fold_counter = 0
    for train, test in KFold(2, shuffle=True).split(X, y):
        training_X, training_y = X[train], y[train]
        test_X, test_y = X[test], y[test]
        classifier = RandomForestClassifier(64)
        classifier.fit(training_X,training_y)
        scores = classifier.predict_proba(test_X)[:,-1]
        fpr, tpr, thresholds = metrics.roc_curve(test_y, scores)
        pyplot.semilogx(fpr,tpr,label="Fold number {0}".format(fold_counter))
        #pyplot.semilogx(fpr,tpr,label="ROC curve".format(fold_counter))
        fold_counter += 1
        with open("proba.log","w") as f:
            scores.sort()
            for s in scores:
                f.write(str(s)+"\n")
    pyplot.xlabel("detector false positive rate")
    pyplot.ylabel("detector true positive rate")
    pyplot.title("Detector ROC curve")
    #pyplot.title("detector cross-validation ROC curves")
    pyplot.legend()
    pyplot.grid()
    pyplot.show()


def get_training_data(benign_path, malicious_path):
    def get_training_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory, path))
        return targets
    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)
    X = [get_peheader_features(path) for path in malicious_paths + benign_paths]
    y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]

    return X, y


def main():
    defaultpath = "./data"
    parser = argparse.ArgumentParser("get windows object vectors for files")
    parser.add_argument("--malware_paths",default=os.path.join(defaultpath,"malware"),help="Path to malware training files")
    parser.add_argument("--benignware_paths",default=os.path.join(defaultpath,"benignware"),help="Path to benignware training files")
    parser.add_argument("--scan_file_path",default=None,help="File to scan")
    parser.add_argument("--evaluate",default=False,action="store_true",help="Perform cross-validation")

    args = parser.parse_args()

    if args.scan_file_path:
        scan_file(args.scan_file_path)
    elif args.malware_paths and args.benignware_paths and not args.evaluate:
        train_detector(args.benignware_paths, args.malware_paths)
    elif args.malware_paths and args.benignware_paths and args.evaluate:
        X, y = get_training_data(args.benignware_paths, args.malware_paths)
        cv_evaluate(X, y)
    else:
        print("[*] You did not specify a path to scan," \
            " nor did you specify paths to malicious and benign training files" \
            " please specify one of these to use the detector.\n")
        parser.print_help()


if __name__ == '__main__':
    main()

