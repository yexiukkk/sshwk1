#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import pickle
import argparse

import numpy
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import FeatureHasher

import pefile


def get_IAT_features(path, hasher):
    # extract Import Address Table features
    print(path)
    IATs = []
    
    try:
        if(pefile.PE(path)):
            pe = pefile.PE(path)
    except:
        IATs.append("PE_ERROR")

    try:
        if(pe.DIRECTORY_ENTRY_IMPORT):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for f in entry.imports:
                    IATs.append(str(f.name))
    except:
        IATs.append("IMPORT_ERROR")

    IAT_features = {}
    for IAT in IATs:
        IAT_features[IAT] = 1

    hashed_features = hasher.transform([IAT_features])
    # do some data munging to get the feature array
    hashed_features = hashed_features.todense()
    hashed_features = numpy.asarray(hashed_features)
    hashed_features = hashed_features[0]

    return hashed_features


def scan_file(path):
    # scan a file to determine if it is malicious or benign
    if not os.path.exists("saved_detector.pkl"):
        print("It appears you haven't trained a detector yet! Do this before scanning files.")
        sys.exit(1)
    with open("saved_detector.pkl", "rb") as saved_detector:
        classifier, hasher = pickle.load(saved_detector)
    features = get_IAT_features(path, hasher)
    result_proba = classifier.predict_proba([features])[:, 1]
    # if the user specifies malware_paths and benignware_paths, train a detector
    if result_proba > 0.5:
        print("It appears this file is malicious!", result_proba)
    else:
        print("It appears this file is benign.", result_proba)


def train_detector(benign_path, malicious_path, hasher):
    # train the detector on the specified training data
    def get_training_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory,path))
        return targets
    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)
    print("Begin Training...")
    X = [get_IAT_features(path,hasher) for path in malicious_paths + benign_paths]
    y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]
    classifier = RandomForestClassifier(64)
    classifier.fit(X, y)
    print("End Training...")
    print("Begin Saving Models...")
    pickle.dump((classifier,hasher),open("saved_detector.pkl","wb+"))
    print("End Saving Models...")


def cv_evaluate(X, y, hasher):
    # use cross-validation to evaluate our model

    from sklearn import metrics
    from matplotlib import pyplot
    from sklearn.model_selection import KFold
    X, y = numpy.array(X), numpy.array(y)
    fold_counter = 0
    for train, test in KFold(2,shuffle=True).split(X,y):
        training_X, training_y = X[train], y[train]
        test_X, test_y = X[test], y[test]
        classifier = RandomForestClassifier(64)
        classifier.fit(training_X, training_y)
        scores = classifier.predict_proba(test_X)[:, -1]
        fpr, tpr, thresholds = metrics.roc_curve(test_y, scores)
        pyplot.semilogx(fpr, tpr, label="Fold number {0}".format(fold_counter))
        #pyplot.semilogx(fpr,tpr,label="ROC curve".format(fold_counter))
        fold_counter += 1
        with open("proba.log", "w") as f:
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


def get_training_data(benign_path, malicious_path, hasher):
    def get_training_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory, path))
        return targets
    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)
    X = [get_IAT_features(path, hasher) for path in malicious_paths + benign_paths]
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

    hasher = FeatureHasher(1000)

    if args.scan_file_path:
        scan_file(args.scan_file_path)
    elif args.malware_paths and args.benignware_paths and not args.evaluate:
        train_detector(args.benignware_paths,args.malware_paths,hasher)
    elif args.malware_paths and args.benignware_paths and args.evaluate:
        X, y = get_training_data(args.benignware_paths,args.malware_paths,hasher)
        cv_evaluate(X,y,hasher)
    else:
        print("[*] You did not specify a path to scan," \
            " nor did you specify paths to malicious and benign training files" \
            " please specify one of these to use the detector.\n")
        parser.print_help()


if __name__ == '__main__':
    main()
