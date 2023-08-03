import { useState, useEffect } from "react";
import {
    Button,
    Card,
    Col,
    Divider,
    Form,
    Input,
    message,
    Row,
    Result,
    Spin,
    Space,
} from "antd";
import axios from "axios";

export const Deploy = () => {
    const [deploymentFeeRecord, setDeploymentFeeRecord] = useState(null);
    const [deployUrl, setDeployUrl] = useState("https://vm.aleo.org/api");
    const [deploymentFee, setDeploymentFee] = useState("1");
    const [loading, setLoading] = useState(false);
    const [feeLoading, setFeeLoading] = useState(false);
    const [privateKey, setPrivateKey] = useState(null);
    const [program, setProgram] = useState(null);
    const [deploymentError, setDeploymentError] = useState(null);
    const [status, setStatus] = useState("");
    const [transactionID, setTransactionID] = useState(null);
    const [worker, setWorker] = useState(null);
    const [messageApi, contextHolder] = message.useMessage();
    function spawnWorker() {
        let worker = new Worker(
            new URL("../../workers/worker.js", import.meta.url),
            { type: "module" },
        );
        worker.addEventListener("message", (ev) => {
            if (ev.data.type == "DEPLOY_TRANSACTION_COMPLETED") {
                let [deployTransaction, url] = ev.data.deployTransaction;
                axios
                    .post(
                        url + "/testnet3/transaction/broadcast",
                        deployTransaction,
                        {
                            headers: {
                                "Content-Type": "application/json",
                            },
                        },
                    )
                    .then((response) => {
                        setFeeLoading(false);
                        setLoading(false);
                        setDeploymentError(null);
                        setTransactionID(response.data);
                    });
            } else if (ev.data.type == "DEPLOYMENT_FEE_ESTIMATION_COMPLETED") {
                let fee = ev.data.deploymentFee;
                setFeeLoading(false);
                setLoading(false);
                setDeploymentError(null);
                setTransactionID(null);
                setDeploymentFee(fee.toString());
            } else if (ev.data.type == "ERROR") {
                setDeploymentError(ev.data.errorMessage);
                setFeeLoading(false);
                setLoading(false);
                setFeeLoading(false);
                setTransactionID(null);
            }
        });
        return worker;
    }

    useEffect(() => {
        if (worker === null) {
            const spawnedWorker = spawnWorker();
            setWorker(spawnedWorker);
            return () => {
                spawnedWorker.terminate();
            };
        }
    }, []);

    function postMessagePromise(worker, message) {
        return new Promise((resolve, reject) => {
            worker.onmessage = (event) => {
                resolve(event.data);
            };
            worker.onerror = (error) => {
                setDeploymentError(error);
                setFeeLoading(false);
                setLoading(false);
                setTransactionID(null);
                reject(error);
            };
            worker.postMessage(message);
        });
    }

    const deploy = async () => {
        setFeeLoading(false);
        setLoading(true);
        setTransactionID(null);
        setDeploymentError(null);

        const feeAmount = parseFloat(feeString());
        if (isNaN(feeAmount)) {
            setDeploymentError("Fee is not a valid number");
            setFeeLoading(false);
            setLoading(false);
            return;
        } else if (feeAmount <= 0) {
            setDeploymentError("Fee must be greater than 0");
            setFeeLoading(false);
            setLoading(false);
            return;
        }

        await postMessagePromise(worker, {
            type: "ALEO_DEPLOY",
            program: programString(),
            privateKey: privateKeyString(),
            fee: feeAmount,
            feeRecord: feeRecordString(),
            url: peerUrl(),
        });
    };

    const estimate = async () => {
        setFeeLoading(true);
        setLoading(false);
        setTransactionID(null);
        setDeploymentError(null);
        messageApi.info(
            "Disclaimer: Fee estimation is experimental and may not represent a correct estimate on any current or future network",
        );
        await postMessagePromise(worker, {
            type: "ALEO_ESTIMATE_DEPLOYMENT_FEE",
            program: programString(),
            url: peerUrl(),
        });
    };

    const demo = async () => {
        setFeeLoading(false);
        setLoading(false);
        setTransactionID(null);
        setDeploymentError(null);
        setProgram(
            "program hello_hello.aleo;\n" +
                "\n" +
                "function hello:\n" +
                "    input r0 as u32.public;\n" +
                "    input r1 as u32.private;\n" +
                "    add r0 r1 into r2;\n" +
                "    output r2 as u32.private;\n",
        );
    };

    const onUrlChange = (event) => {
        if (event.target.value !== null) {
            setDeployUrl(event.target.value);
        }
        return deployUrl;
    };

    const onProgramChange = (event) => {
        if (event.target.value !== null) {
            setProgram(event.target.value);
        }
        setTransactionID(null);
        setDeploymentError(null);
        return program;
    };

    const onDeploymentFeeChange = (event) => {
        if (event.target.value !== null) {
            setDeploymentFee(event.target.value);
        }
        setTransactionID(null);
        setDeploymentError(null);
        return deploymentFee;
    };

    const onDeploymentFeeRecordChange = (event) => {
        if (event.target.value !== null) {
            setDeploymentFeeRecord(event.target.value);
        }
        setTransactionID(null);
        setDeploymentError(null);
        return deploymentFeeRecord;
    };

    const onPrivateKeyChange = (event) => {
        if (event.target.value !== null) {
            setPrivateKey(event.target.value);
        }
        setTransactionID(null);
        setDeploymentError(null);
        return privateKey;
    };

    const layout = { labelCol: { span: 3 }, wrapperCol: { span: 21 } };
    const privateKeyString = () => (privateKey !== null ? privateKey : "");
    const programString = () => (program !== null ? program : "");
    const feeRecordString = () =>
        deploymentFeeRecord !== null ? deploymentFeeRecord : "";
    const transactionIDString = () =>
        transactionID !== null ? transactionID : "";
    const deploymentErrorString = () =>
        deploymentError !== null ? deploymentError : "";
    const feeString = () => (deploymentFee !== null ? deploymentFee : "");
    const peerUrl = () => (deployUrl !== null ? deployUrl : "");

    return (
        <Card
            title="Deploy Program"
            style={{ width: "100%", borderRadius: "20px" }}
            bordered={false}
            extra={
                <Button
                    type="primary"
                    shape="round"
                    size="middle"
                    onClick={demo}
                >
                    Demo
                </Button>
            }
        >
            <Form {...layout}>
                <Divider />
                <Form.Item label="Program" colon={false}>
                    <Input.TextArea
                        size="large"
                        rows={10}
                        placeholder="Program"
                        style={{
                            whiteSpace: "pre-wrap",
                            overflowWrap: "break-word",
                        }}
                        value={programString()}
                        onChange={onProgramChange}
                    />
                </Form.Item>
                <Divider />
                <Form.Item
                    label="Private Key"
                    colon={false}
                    validateStatus={status}
                >
                    <Input.TextArea
                        name="private_key"
                        size="small"
                        placeholder="Private Key"
                        allowClear
                        onChange={onPrivateKeyChange}
                        value={privateKeyString()}
                    />
                </Form.Item>
                <Form.Item
                    label="Peer Url"
                    colon={false}
                    validateStatus={status}
                >
                    <Input.TextArea
                        name="Peer URL"
                        size="middle"
                        placeholder="Aleo Network Node URL"
                        allowClear
                        onChange={onUrlChange}
                        value={peerUrl()}
                    />
                </Form.Item>
                <Form.Item label="Fee" colon={false} validateStatus={status}>
                    <Input.TextArea
                        name="Fee"
                        size="small"
                        placeholder="Fee"
                        allowClear
                        onChange={onDeploymentFeeChange}
                        value={feeString()}
                    />
                </Form.Item>
                <Form.Item
                    label="Fee Record"
                    colon={false}
                    validateStatus={status}
                >
                    <Input.TextArea
                        name="Fee Record"
                        size="small"
                        placeholder="Record used to pay deployment fee"
                        allowClear
                        onChange={onDeploymentFeeRecordChange}
                        value={feeRecordString()}
                    />
                </Form.Item>
                <Row justify="center">
                    <Col justify="center">
                        <Space>
                            <Button
                                type="primary"
                                shape="round"
                                size="middle"
                                onClick={deploy}
                            >
                                Deploy
                            </Button>
                            {contextHolder}
                            <Button
                                type="primary"
                                shape="round"
                                size="middle"
                                onClick={estimate}
                            >
                                Estimate Fee
                            </Button>
                        </Space>
                    </Col>
                </Row>
            </Form>
            <Row
                justify="center"
                gutter={[16, 32]}
                style={{ marginTop: "48px" }}
            >
                {loading === true && (
                    <Spin tip="Attempting to Deploy Program..." size="large" />
                )}
                {feeLoading === true && loading === false && (
                    <Spin tip="Estimating Deployment Fee..." size="large" />
                )}
                {transactionID !== null && (
                    <Result
                        status="success"
                        title="Deployment Successful!"
                        subTitle={"Transaction ID: " + transactionIDString()}
                    />
                )}
                {deploymentError !== null && (
                    <Result
                        status="error"
                        title="Error"
                        subTitle={"Error: " + deploymentErrorString()}
                    />
                )}
            </Row>
        </Card>
    );
};
