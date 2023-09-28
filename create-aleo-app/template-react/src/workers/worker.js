import * as aleo from "@aleohq/sdk";

await aleo.initializeWasm();
await aleo.initThreadPool(10);

const defaultHost = "https://vm.aleo.org/api";
const keyProvider = new aleo.AleoKeyProvider();
const programManager = new aleo.ProgramManager(defaultHost, keyProvider, undefined);

keyProvider.useCache(true);

self.postMessage({
    type: "ALEO_WORKER_READY",
});

let lastLocalProgram = null;
self.addEventListener("message", (ev) => {
    if (ev.data.type === "ALEO_EXECUTE_PROGRAM_LOCAL") {
        const { localProgram, aleoFunction, inputs, privateKey } = ev.data;

        console.log("Web worker: Executing function locally...");
        let startTime = performance.now();

        (async function () {
            try {
                // Ensure the program is valid and that it contains the function specified
                const program = programManager.createProgramFromSource(localProgram);
                const program_id = program.id();
                if (!program.hasFunction(aleoFunction)) {
                    throw `Program ${program_id} does not contain function ${aleoFunction}`;
                }
                const cacheKey = `${program_id}:${aleoFunction}`;

                // Get the program imports
                const imports = programManager.networkClient.getProgramImports(localProgram);

                // Get the proving and verifying keys for the function
                if (lastLocalProgram !== localProgram) {
                    const keys = programManager.executionEngine.synthesizeKeypair(localProgram, aleoFunction);
                    programManager.keyProvider.cacheKeys(cacheKey, [keys.provingKey(), keys.verifyingKey()]);
                    lastLocalProgram = localProgram;
                }

                // Pass the cache key to the execute function
                const keyParams = new aleo.AleoKeyProviderParams({"cacheKey": cacheKey});

                // Execute the function locally
                let response = await programManager.executeOffline(
                    localProgram,
                    aleoFunction,
                    inputs,
                    false,
                    imports,
                    keyParams,
                    undefined,
                    undefined,
                    aleo.PrivateKey.from_string(privateKey)
                );

                // Return the outputs to the main thread
                console.log(`Web worker: Local execution completed in ${performance.now() - startTime} ms`);
                const outputs = response.getOutputs();
                let execution = response.getExecution();
                if (execution) {
                    aleo.verifyFunctionExecution(execution, keyProvider.getKeys(cacheKey)[1], program, "hello");
                    execution = execution.toString();
                    console.log("Execution verified successfully: " + execution);
                } else {
                    execution = "";
                }

                console.log(`Function execution response: ${outputs}`);
                self.postMessage({
                    type: "OFFLINE_EXECUTION_COMPLETED",
                    outputs: {outputs: outputs, execution: execution}
                });
            } catch (error) {
                console.error(error);
                self.postMessage({
                    type: "ERROR",
                    errorMessage: error.toString(),
                });
            }
        })();
    } else if (ev.data.type === "ALEO_EXECUTE_PROGRAM_ON_CHAIN") {
        const {
            remoteProgram,
            aleoFunction,
            inputs,
            privateKey,
            fee,
            feeRecord,
            url,
        } = ev.data;

        console.log("Web worker: Creating execution...");
        let startTime = performance.now();

        (async function () {
            try {
                const privateKeyObject = aleo.PrivateKey.from_string(privateKey)
                // Ensure the program is valid and that it contains the function specified
                const program = await programManager.networkClient.getProgramObject(remoteProgram);
                const program_id = program.id();
                if (!program.hasFunction(aleoFunction)) {
                    throw `Program ${program_id} does not contain function ${aleoFunction}`;
                }

                // Get the proving and verifying keys for the function
                const cacheKey = `${program_id}:${aleoFunction}`;
                if (!programManager.keyProvider.containsKeys(cacheKey)) {
                    console.log(`Web worker: Synthesizing proving & verifying keys for: '${program_id}:${aleoFunction}'`);
                    const keys = programManager.executionEngine.synthesizeKeypair(remoteProgram, aleoFunction);
                    programManager.keyProvider.cacheKeys(cacheKey, [keys.provingKey(), keys.verifyingKey()]);
                }

                // Pass the cache key to the execute function
                const keyParams = new aleo.AleoKeyProviderParams({"cacheKey": cacheKey})

                // Set the host to the provided URL if provided
                if (typeof url === "string") { programManager.setHost(url); }
                const transaction = await programManager.execute(
                    program_id,
                    aleoFunction,
                    fee,
                    inputs,
                    undefined,
                    keyParams,
                    feeRecord,
                    undefined,
                    undefined,
                    privateKeyObject
                );

                // Return the transaction id to the main thread
                console.log(`Web worker: On-chain execution transaction created in ${performance.now() - startTime} ms`);
                self.postMessage({
                    type: "EXECUTION_TRANSACTION_COMPLETED",
                    executeTransaction: transaction,
                });
            } catch (error) {
                console.error(`Error creating execution transaction: ${error}`);
                self.postMessage({
                    type: "ERROR",
                    errorMessage: error.toString(),
                });
            } finally {
                programManager.setHost(defaultHost);
            }
        })();
    } else if (ev.data.type === "ALEO_ESTIMATE_EXECUTION_FEE") {
        const { remoteProgram, aleoFunction, inputs, url } =
            ev.data;

        console.log("Web worker: Estimating execution fee...");
        let startTime = performance.now();

        (async function () {
            try {
                // Ensure the program is valid and that it contains the function specified
                const program = await programManager.networkClient.getProgramObject(remoteProgram);
                const program_id = program.id();
                if (!program.getFunctions().includes(aleoFunction)) {
                    throw `Program ${program_id} does not contain function ${aleoFunction}`;
                }
                const cacheKey = `${program_id}:${aleoFunction}`;
                const imports = await programManager.networkClient.getProgramImports(remoteProgram);

                // Get the proving and verifying keys for the function
                if (!programManager.keyProvider.containsKeys(cacheKey)) {
                    console.log(`Web worker: Synthesizing proving & verifying keys for: '${program_id}:${aleoFunction}'`);
                    const keys = programManager.executionEngine.synthesizeKeypair(remoteProgram, aleoFunction);
                    programManager.keyProvider.cacheKeys(cacheKey, [keys.provingKey(), keys.verifyingKey()]);
                }

                // Estimate the execution fee
                const [provingKey, verifyingKey] = programManager.keyProvider.getKeys(cacheKey);
                let executeFee = await programManager.executionEngine.estimateExecutionFee(
                    new aleo.PrivateKey(),
                    remoteProgram,
                    aleoFunction,
                    inputs,
                    url,
                    false,
                    imports,
                    provingKey,
                    verifyingKey,
                );

                // Return the execution fee estimate to the main thread
                console.log(`Web worker: Execution fee estimated in ${performance.now() - startTime} ms`);
                console.log(`Execution Fee Estimation: ${executeFee} microcrdits`);
                self.postMessage({
                    type: "EXECUTION_FEE_ESTIMATION_COMPLETED",
                    executionFee: Number(executeFee) / 1000000 + 0.01,
                });
            } catch (error) {
                console.error(error);
                self.postMessage({
                    type: "ERROR",
                    errorMessage: error.toString(),
                });
            }
        })();
    } else if (ev.data.type === "ALEO_ESTIMATE_DEPLOYMENT_FEE") {
        const { program, url } = ev.data;

        console.log("Web worker: Estimating deployment fee...");

        let startTime = performance.now();
        (async function () {
            try {
                const imports = await programManager.networkClient.getProgramImports(program);
                console.log("Estimating deployment fee..");
                let deploymentFee =
                    await programManager.executionEngine.estimateDeploymentFee(
                        program,
                        false,
                        imports,
                    );

                // Return the deployment fee estimate to the main thread
                console.log(`Web worker: Deployment fee estimation completed in ${performance.now() - startTime} ms`);
                console.log(`Deployment Fee Estimation: ${deploymentFee} microcredits`);
                self.postMessage({
                    type: "DEPLOYMENT_FEE_ESTIMATION_COMPLETED",
                    deploymentFee: Number(deploymentFee) / 1000000 + 0.01,
                });
            } catch (error) {
                console.error(error);
                self.postMessage({
                    type: "ERROR",
                    errorMessage: error.toString(),
                });
            }
        })();
    } else if (ev.data.type === "ALEO_TRANSFER") {
        const {
            privateKey,
            amountCredits,
            recipient,
            transfer_type,
            amountRecord,
            fee,
            feeRecord,
            url,
        } = ev.data;

        console.log(
            `Web worker: Creating transfer of type ${transfer_type}...`,
        );
        let startTime = performance.now();

        (async function () {
            try {
                // Set the host to the provided URL if provided
                if (typeof url === "string") { programManager.setHost(url); }

                // Create the transfer transaction and submit it to the network
                const transaction = await programManager.transfer(
                    amountCredits,
                    recipient,
                    transfer_type,
                    fee,
                    undefined,
                    amountRecord,
                    feeRecord,
                    aleo.PrivateKey.from_string(privateKey)
                );

                // Return the transaction id to the main thread
                console.log(`Web worker: Transfer transaction ${transaction} created in ${performance.now() - startTime} ms`);
                self.postMessage({
                    type: "TRANSFER_TRANSACTION_COMPLETED",
                    transferTransaction: transaction,
                });
            } catch (error) {
                console.error(error);
                self.postMessage({
                    type: "ERROR",
                    errorMessage: error.toString(),
                });
            } finally {
                programManager.setHost(defaultHost);
            }
        })();
    } else if (ev.data.type === "ALEO_DEPLOY") {
        const { program, privateKey, fee, feeRecord, url } = ev.data;

        console.log("Web worker: Creating deployment...");

        let startTime = performance.now();
        (async function () {
            try {
                // Set the network client host if specified
                if (typeof url === "string") { programManager.setHost(url); }

                // Check if the program is valid
                const programObject = programManager.createProgramFromSource(program);

                // Check if the program already exists on the network. If so, throw an error
                let programExists = false;
                try {
                    await programManager.networkClient.getProgram(programObject.id());
                    programExists = true;
                } catch (e) {
                    console.log(
                        `Program not found on the Aleo Network - proceeding with deployment...`,
                    );
                }

                if (programExists) {
                    throw `Program ${programObject.id()} already exists on the network`;
                }

                console.log("fee is: ", fee);
                // Create the deployment transaction and submit it to the network
                let transaction = await programManager.deploy(
                    program,
                    fee,
                    undefined,
                    feeRecord,
                    aleo.PrivateKey.from_string(privateKey),
                )

                // Return the transaction id to the main thread
                console.log(`Web worker: Deployment transaction ${transaction} created in ${performance.now() - startTime} ms`);
                self.postMessage({
                    type: "DEPLOY_TRANSACTION_COMPLETED",
                    deployTransaction: transaction,
                });
            } catch (error) {
                console.log(error);
                self.postMessage({
                    type: "ERROR",
                    errorMessage: error.toString(),
                });
            } finally {
                programManager.setHost(defaultHost);
            }
        })();
    } else if (ev.data.type === "ALEO_SPLIT") {
        const { splitAmount, record, privateKey, url } = ev.data;

        console.log("Web worker: Creating split...");

        let startTime = performance.now();
        (async function () {
            try {
                // Set the network client host if specified
                if (typeof url === "string") { programManager.setHost(url); }

                // Create the split transaction and submit to the network
                const transaction = await programManager.split(
                    splitAmount,
                    record,
                    aleo.PrivateKey.from_string(privateKey)
                );

                // Return the transaction id to the main thread
                console.log(`Web worker: Split transaction ${transaction} created in ${performance.now() - startTime} ms`);
                self.postMessage({
                    type: "SPLIT_TRANSACTION_COMPLETED",
                    splitTransaction: transaction,
                });
            } catch (error) {
                console.log(error);
                self.postMessage({
                    type: "ERROR",
                    errorMessage: error.toString(),
                });
            } finally {
                programManager.setHost(defaultHost);
            }
        })();
    } else if (ev.data.type === "ALEO_JOIN") {
        const { recordOne, recordTwo, fee, feeRecord, privateKey, url } =
            ev.data;

        console.log("Web worker: Creating join...");

        let startTime = performance.now();
        (async function () {

            try {
                // Set the network client host if specified
                if (typeof url === "string") { programManager.setHost(url); }

                // Create the join transaction and submit it to the network
                const transaction = await programManager.join(
                    recordOne,
                    recordTwo,
                    fee,
                    undefined,
                    feeRecord,
                    aleo.PrivateKey.from_string(privateKey),
                );

                // Return the transaction id to the main thread
                console.log(`Web worker: Join transaction ${transaction} created in ${performance.now() - startTime} ms`);
                self.postMessage({
                    type: "JOIN_TRANSACTION_COMPLETED",
                    joinTransaction: transaction,
                });
            } catch (error) {
                console.log(error);
                self.postMessage({
                    type: "ERROR",
                    errorMessage: error.toString(),
                });
            } finally {
                programManager.setHost(defaultHost);
            }
        })();
    }
});
